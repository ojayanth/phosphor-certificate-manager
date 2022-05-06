#include "config.h"

#include "acf_manager.hpp"

#include <CeLogin.h>
#include <CeLoginAsnV1.h>
#include <CeLoginJson.h>
#include <CeLoginUtil.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sstream>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace acf
{
namespace cert
{
using namespace phosphor::logging;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;

using Reason = xyz::openbmc_project::Certs::InvalidCertificate::REASON;

constexpr auto ACF_FILE_PATH = "/etc/acf/service.acf";
constexpr auto PROD_PUB_KEY_FILE_PATH = "/srv/ibm-acf/ibmacf-prod.key";
constexpr auto PROD_BACKUP_PUB_KEY_FILE_PATH = "/srv/ibm-acf/ibmacf-prod-backup.key";
constexpr auto DEV_PUB_KEY_FILE_PATH = "/srv/ibm-acf/ibmacf-dev.key";
constexpr auto DBUS_INVENTORY_SYSTEM_OBJECT =
    "/xyz/openbmc_project/inventory/system";
constexpr auto DBUS_INVENTORY_ASSET_INTERFACE =
    "xyz.openbmc_project.Inventory.Decorator.Asset";
constexpr auto DBUS_SERIAL_NUM_PROP = "SerialNumber";
constexpr auto UNSET_SERIAL_NUM_KEYWORD = "UNSET";
constexpr auto BLANK_SERIAL_NUMBER = "       ";
constexpr auto DBUS_SOFTWARE_OBJECT = "/xyz/openbmc_project/software";
constexpr auto DBUS_FIELDMODE_INTERFACE =
    "xyz.openbmc_project.Control.FieldMode";
constexpr auto DBUS_FIELD_MODE_PROP = "FieldModeEnabled";
const int FAILURE = -1;

/** @brief Implementation for readBinaryFile
 *  Read file contents into buffer
 *
 *  @param[in] fileNameParm - Path of file.
 *
 *  @param[out] bufferParm - Buffer to store contents of file.
 *
 *  @return Status of if read was successful.
 */
static bool readBinaryFile(const std::string fileNameParm,
                           std::vector<uint8_t>& bufferParm)
{
    std::ifstream sInputFile;
    if (!fileNameParm.empty())
    {
        sInputFile.open(fileNameParm.c_str(), std::ios::in | std::ios::binary);
        if (sInputFile.is_open())
        {
            // Get the size of the file
            sInputFile.seekg(0, std::ios::end);
            std::streampos size = sInputFile.tellg();
            sInputFile.seekg(0, std::ios::beg);

            bufferParm.reserve(size);
            bufferParm.assign(size, 0);

            sInputFile.read((char*)bufferParm.data(), size);
            sInputFile.close();

            return true;
        }
        else
        {
            log<level::ERR>("Failed to open file ",
                            entry("FILENAME=%s", fileNameParm.c_str()));
        }
    }
    else
    {
        log<level::ERR>("Filename empty");
    }

    return false;
}
/** @brief Implementation for readMachineSerialNumberProperty
 *  Make dbus call to get the bmc serial number
 *
 *  @param[in] obj - dbus object.
 *
 *  @param[in] inf - dbus interface.
 *
 *  @param[in] prop - dbus property.
 *
 *  @return Status of dbus call.
 */
static std::string readMachineSerialNumberProperty(const std::string& obj,
                                                   const std::string& inf,
                                                   const std::string& prop)
{
    std::string propSerialNum{};
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.Inventory.Manager", obj.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(inf);
    properties.append(prop);
    try
    {
        auto result = bus.call(properties);
        if (!result.is_method_error())
        {
            std::variant<std::string> val;
            result.read(val);
            if (auto pVal = std::get_if<std::string>(&val))
            {
                propSerialNum.assign((pVal->data()), pVal->size());
            }
            else
            {
                log<level::ERR>("could not get the host's serial number\n");
            }
        }
    }
    catch (const std::exception& exc)
    {
        log<level::ERR>("dbus call for getting serial number failed:  ",
                        entry("Exception %s", exc.what()));
        propSerialNum = "";
    }
    return propSerialNum;
}
/** @brief Implementation for readFieldModeProperty
 *  Make dbus call to get field mode property state
 *
 *  @param[in] obj - dbus object.
 *
 *  @param[in] inf - dbus interface.
 *
 *  @param[in] prop - dbus property.
 *
 *  @return Status of dbus call.
 */
static int readFieldModeProperty(const std::string& obj, const std::string& inf,
                                 const std::string& prop)
{
    bool propBool = false;
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.Software.BMC.Updater", obj.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(inf);
    properties.append(prop);
    try
    {
        auto result = bus.call(properties);
        if (!result.is_method_error())
        {
            std::variant<bool> val{false};
            result.read(val);
            if (auto pVal = std::get_if<bool>(&val))
            {
                log<level::ERR>(
                    "dbus call for getting FieldModeProperty failed ");
                propBool = (*pVal);
            }
        }
    }
    catch (const std::exception& exc)
    {
        log<level::ERR>("dbus call failure ",
                        entry("Exception: %s", exc.what()));
        return FAILURE;
    }

    return (int)propBool;
}

/** @brief Implementation for verifyAcfSerialNumberAndExpiration
 *  Perform validation of ACF.
 *  This verifies the signature,
 *  checks that the serial number stored on ACF matches BMC serial number,
 *  checks that the expiration on ACF isn't past the current bmc time
 *
 *  @param[in] accessControlFile - ACF contents.
 *
 *  @param[in] publicKeyFile - Public key contents.
 *
 *  @param[out] sDate - Expiration date of ACF file.
 *
 *  @return Status of call. Success indicates verification was successful.
 */
static CeLogin::CeLoginRc
    verifyAcfSerialNumberAndExpiration(std::vector<uint8_t>& accessControlFile,
                                       std::vector<uint8_t>& publicKeyFile,
                                       std::string& sDate)
{
    CeLogin::CELoginSequenceV1* sDecodedAsn = NULL;
    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;
    CeLogin::CeLoginJsonData* sJsonData = NULL;

    sRc = decodeAndVerifySignature(
        accessControlFile.data(), accessControlFile.size(),
        publicKeyFile.data(), publicKeyFile.size(), sDecodedAsn);

    if (CeLogin::CeLoginRc::Success == sRc)
    {
        log<level::INFO>("Signature verified");

        std::string mSerialNumber = readMachineSerialNumberProperty(
            DBUS_INVENTORY_SYSTEM_OBJECT, DBUS_INVENTORY_ASSET_INTERFACE,
            DBUS_SERIAL_NUM_PROP);

        // If serial number is empty on machine set as UNSET for check with acf
        if (mSerialNumber.empty() || (mSerialNumber == BLANK_SERIAL_NUMBER))
        {
            mSerialNumber = UNSET_SERIAL_NUM_KEYWORD;
        }
        sJsonData = (CeLogin::CeLoginJsonData*)OPENSSL_malloc(
            sizeof(CeLogin::CeLoginJsonData));
        if (sJsonData)
        {
            memset(sJsonData, 0x00, sizeof(CeLogin::CeLoginJsonData));
        }
        else
        {
            log<level::ERR>("malloc failed");
            elog<InternalFailure>();
        }

        // Verify system serial number is in machine list (and get the
        // authorization)
        const uint64_t serialNumberLengthParm = mSerialNumber.length();
        sRc = CeLogin::decodeJson(
            (const char*)sDecodedAsn->sourceFileData->data,
            sDecodedAsn->sourceFileData->length, mSerialNumber.c_str(),
            serialNumberLengthParm, *sJsonData);
        if (CeLogin::CeLoginRc::Success == sRc)
        {
            log<level::INFO>("Serial Number matches");
            // Check if time is expired
            uint64_t sExpirationTime = 0;
            std::time_t timeSinceUnixEpocInSecondsParm = std::time(NULL);
            sRc = CeLogin::isTimeExpired(sJsonData, sExpirationTime,
                                         timeSinceUnixEpocInSecondsParm);
            if (CeLogin::CeLoginRc::Success == sRc)
            {
                // YYYYMMDD
                char sTimeStr[20];
                sprintf(sTimeStr, "%04u-%02u-%02u",
                        sJsonData->mExpirationDate.mYear,
                        sJsonData->mExpirationDate.mMonth,
                        sJsonData->mExpirationDate.mDay);
                sDate = sTimeStr;
            }
            else
            {
                sRc = CeLogin::CeLoginRc::AcfExpired;
                log<level::ERR>("ACF time expired");
            }
        }
        else
        {
            sRc = CeLogin::CeLoginRc::SerialNumberMismatch;
            log<level::ERR>("Serial Number does not match");
        }
    }
    else if (CeLogin::CeLoginRc::SignatureNotValid == sRc)
    {
        log<level::ERR>("Signature is not valid");
    }
    else
    {
        log<level::ERR>("Error: ", entry("sRc=%d", (int)sRc));
    }

    if (sDecodedAsn)
    {
        CELoginSequenceV1_free(sDecodedAsn);
    }
    if (sJsonData)
    {
        OPENSSL_free(sJsonData);
    }
    return sRc;
}

acf_info ACFCertMgr::installACF(std::vector<uint8_t> accessControlFile)
{
    bool isAcfInstalled = false;
    std::string sDate;
    // delete acf file if accessControlFile is empty
    if (accessControlFile.empty())
    {
        try
        {
            isAcfInstalled = std::filesystem::exists(ACF_FILE_PATH);
        }
        catch (std::filesystem::filesystem_error& e)
        {
            log<level::ERR>("Filesystem error", entry("error: %s", e.what()));
        }
        catch (const InternalFailure& e)
        {
            log<level::ERR>("Internal error", entry("error: %s", e.what()));
            elog<InternalFailure>();
        }

        if (isAcfInstalled)
        {
            try
            {
                std::filesystem::remove(ACF_FILE_PATH);
                isAcfInstalled = false;
                log<level::INFO>("Removed ACF");
            }
            catch (std::filesystem::filesystem_error& e)
            {
                log<level::ERR>("Filesystem error",
                                entry("error: %s", e.what()));
                elog<InternalFailure>();
            }
            catch (const InternalFailure& e)
            {
                log<level::ERR>("Internal error", entry("error: %s", e.what()));
                elog<InternalFailure>();
            }
        }
        return std::make_tuple(accessControlFile, isAcfInstalled, sDate);
    }

    bool prodKeyExists = false;
    bool devKeyExists = false;
    bool prodBackupKeyExists = false;
    try
    {
        prodKeyExists = std::filesystem::exists(PROD_PUB_KEY_FILE_PATH);
        prodBackupKeyExists = std::filesystem::exists(PROD_BACKUP_PUB_KEY_FILE_PATH);
        devKeyExists = std::filesystem::exists(DEV_PUB_KEY_FILE_PATH);
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        log<level::ERR>("filesystem_error error");
        elog<InternalFailure>();
    }

    // This should never occur
    if (!((prodKeyExists || devKeyExists || prodBackupKeyExists)))
    {
        log<level::ERR>("Neither prod or dev key exist. This shouldn't happen");
        elog<InternalFailure>();
    }

    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;

    if (prodKeyExists)
    {
        std::vector<uint8_t> sPublicKeyFile;
        if (readBinaryFile(PROD_PUB_KEY_FILE_PATH, sPublicKeyFile))
        {
            sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                     sPublicKeyFile, sDate);
        }
        else
        {
            log<level::ERR>("cannot read production key file");
            elog<InternalFailure>();
        }
    }
    if (prodBackupKeyExists && sRc != CeLogin::CeLoginRc::Success)
    {
        std::vector<uint8_t> sPublicKeyFile;
        if (readBinaryFile(PROD_BACKUP_PUB_KEY_FILE_PATH, sPublicKeyFile))
        {
            sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                     sPublicKeyFile, sDate);
        }
        else
        {
            log<level::ERR>("cannot read production key file");
            elog<InternalFailure>();
        }
    }
    // If ACF check against production key failed, check against the development
    // key.
    if (devKeyExists && sRc != CeLogin::CeLoginRc::Success)
    {
        // Only want to check signature against development signed public key if
        // FieldModeProperty is not enabled
        int fieldModeEnabled = readFieldModeProperty(DBUS_SOFTWARE_OBJECT,
                                                     DBUS_FIELDMODE_INTERFACE,
                                                     DBUS_FIELD_MODE_PROP);
        if (devKeyExists && (fieldModeEnabled == 0))
        {

            std::vector<uint8_t> sPublicKeyFile;
            if (readBinaryFile(DEV_PUB_KEY_FILE_PATH, sPublicKeyFile))
            {
                sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                         sPublicKeyFile, sDate);
            }
            else
            {
                log<level::ERR>("cannot read dev key file");
                elog<InternalFailure>();
            }
        }
    }

    if (CeLogin::CeLoginRc::Success == sRc)
    {
        log<level::INFO>("ACF validation success");
        try
        {
            // If service.acf exists, remove before writing.
            if (std::filesystem::exists(ACF_FILE_PATH))
            {
                std::filesystem::remove(ACF_FILE_PATH);
            }
            std::ofstream acf_file(ACF_FILE_PATH);
            std::ostream_iterator<uint8_t> output_iterator(acf_file);
            std::copy(accessControlFile.begin(), accessControlFile.end(),
                      output_iterator);
            isAcfInstalled = std::filesystem::exists(ACF_FILE_PATH);
        }
        catch (const std::filesystem::filesystem_error& e)
        {
            log<level::ERR>("Copying acf file to destination failed");
            elog<InternalFailure>();
        }
    }
    else
    {
        log<level::ERR>("ACF validation failed");
        // If upload/validate failed return failure
        elog<InvalidCertificate>(Reason("ACF validation failed"));
    }

    return std::make_tuple(accessControlFile, isAcfInstalled, sDate);
}

std::tuple<std::vector<uint8_t>, bool, std::string> ACFCertMgr::getACFInfo(void)
{
    bool isAcfInstalled = false;
    bool prodKeyExists = false;
    bool devKeyExists = false;
    bool prodBackupKeyExists = false;
    std::string sDate;
    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;
    std::vector<uint8_t> accessControlFile;

    try
    {
        isAcfInstalled = std::filesystem::exists(ACF_FILE_PATH);
        prodKeyExists = std::filesystem::exists(PROD_PUB_KEY_FILE_PATH);
        prodBackupKeyExists = std::filesystem::exists(PROD_BACKUP_PUB_KEY_FILE_PATH);
        devKeyExists = std::filesystem::exists(DEV_PUB_KEY_FILE_PATH);
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        log<level::ERR>("filesystem_error error");
        elog<InternalFailure>();
    }

    // ACF and production or development key should exist otherwise exit
    if (!((prodKeyExists || devKeyExists || prodBackupKeyExists ) && isAcfInstalled))
    {
        // Returns empty data as file is not installed
        return std::make_tuple(accessControlFile, isAcfInstalled, sDate);
    }

    if (!readBinaryFile(ACF_FILE_PATH, accessControlFile))
    {
        // throw as not able to read acf file installed
        log<level::ERR>("Cannot read acf file");
        elog<InternalFailure>();
    }

    if (prodKeyExists)
    {
        std::vector<uint8_t> sPublicKeyFile;
        if (readBinaryFile(PROD_PUB_KEY_FILE_PATH, sPublicKeyFile))
        {
            sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                     sPublicKeyFile, sDate);
        }
        else
        {
            log<level::ERR>("Cannot read production key file");
            elog<InternalFailure>();
        }
    }

    if (prodBackupKeyExists && sRc != CeLogin::CeLoginRc::Success)
    {
        std::vector<uint8_t> sPublicKeyFile;
        if (readBinaryFile(PROD_BACKUP_PUB_KEY_FILE_PATH, sPublicKeyFile))
        {
            sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                     sPublicKeyFile, sDate);
        }
        else
        {
            log<level::ERR>("cannot read production key file");
            elog<InternalFailure>();
        }
    }

    if (devKeyExists && sRc != CeLogin::CeLoginRc::Success)
    {
        // Only want to check signature against development signed public key if
        // FieldModeProperty is not enabled
        int fieldModeEnabled = readFieldModeProperty(DBUS_SOFTWARE_OBJECT,
                                                     DBUS_FIELDMODE_INTERFACE,
                                                     DBUS_FIELD_MODE_PROP);
        if (devKeyExists && (fieldModeEnabled == 0))
        {
            std::vector<uint8_t> sPublicKeyFile;
            if (readBinaryFile(DEV_PUB_KEY_FILE_PATH, sPublicKeyFile))
            {
                sRc = verifyAcfSerialNumberAndExpiration(accessControlFile,
                                                         sPublicKeyFile, sDate);
            }
            else
            {
                log<level::ERR>("cannot read dev key file");
                elog<InternalFailure>();
            }
        }
    }

    if (sRc != CeLogin::CeLoginRc::Success)
    {
        isAcfInstalled = false;
    }

    return std::make_tuple(accessControlFile, isAcfInstalled, sDate);
}

} // namespace cert
} // namespace acf

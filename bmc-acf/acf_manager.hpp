#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/event.hpp>
#include <xyz/openbmc_project/Certs/ACF/server.hpp>
typedef std::tuple<std::vector<uint8_t>, bool, std::string> acf_info;

namespace acf
{
namespace cert
{

class ACFCertMgr;

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::ACF>;
using Mgr = acf::cert::ACFCertMgr;

/** @class Manager
 *  @brief Implementation for the
 *         xyz.openbmc_project.Certs.ACF.Manager DBus API.
 */
class ACFCertMgr : public CreateIface
{
  public:
    ACFCertMgr() = delete;
    ACFCertMgr(const ACFCertMgr&) = delete;
    ACFCertMgr& operator=(const ACFCertMgr&) = delete;
    ACFCertMgr(ACFCertMgr&&) = delete;
    ACFCertMgr& operator=(ACFCertMgr&&) = delete;
    virtual ~ACFCertMgr() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] event - sd event handler.
     */
    ACFCertMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
               const char* path) :
        CreateIface(bus, path),
        bus(bus), event(event), objectPath(path), lastEntryId(0){};

    /** @brief Implementation for InstallACF
     *  Replace the existing ACF with another ACF
     *
     *  @param[in] ACFfile - ACF contents.
     *
     *  @return ACF related information.
     */
    acf_info installACF(std::vector<uint8_t>) override;

    /** @brief Implementation for GetACFInfo
     *  Returns contents of installed ACF
     *
     *  @return ACF related information.
     */
    acf_info getACFInfo(void) override;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;
    // sdevent Event handle
    sdeventplus::Event& event;
    /** @brief object path */
    std::string objectPath;
    /** @brief Id of the last certificate entry */
    uint32_t lastEntryId;
};

} // namespace cert
} // namespace acf

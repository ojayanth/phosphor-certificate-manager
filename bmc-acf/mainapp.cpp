#include "config.h"

#include "acf_manager.hpp"

#include <sdeventplus/event.hpp>
#include <string>

int main(int /*argc*/, char** /*argv*/)
{
    auto bus = sdbusplus::bus::new_default();
    static constexpr auto objPath = "/xyz/openbmc_project/certs/ACF";

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath);

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    acf::cert::ACFCertMgr manager(bus, event, objPath);

    std::string busName = "xyz.openbmc_project.Certs.ACF.Manager";
    bus.request_name(busName.c_str());
    event.loop();
    return 0;
}

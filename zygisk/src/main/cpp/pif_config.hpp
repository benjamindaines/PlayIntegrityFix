#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace pif {
    struct Config {
        std::unordered_map<std::string, std::string> propMap;
        bool spoofBuild = true;
        bool spoofProps = true;
        bool spoofProvider = false;
        bool spoofSignature = false;
        bool debug = false;
        std::string deviceInitialSdkInt = "21";
        std::string securityPatch;
        std::string buildId;
        bool spoofVendingSdk = false;
        bool spoofVendingBuild = false;

        [[nodiscard]] bool needsDex() const {
            return spoofProvider || spoofSignature;
        }
    };

    // Multi-profile container. A single pif.prop may declare any number of
    // named profiles via [profile <name>] headers plus a routing table that
    // maps a process name to a profile name. Keys that appear before the first
    // header belong to the implicit profile named "default", which preserves
    // single-profile (legacy) file behavior and is the fallback target.
    //
    // Routing keys are exact process names (Zygisk nice_name), for example
    // "com.google.android.gms.unstable" or
    // "com.google.android.apps.messaging:rcs". A process whose name has no
    // route is not injected.
    struct ConfigBundle {
        std::unordered_map<std::string, Config> profiles;    // profile name -> config
        std::unordered_map<std::string, std::string> routes; // process name -> profile name
    };

    // Parse the entire configuration text into all declared profiles and the
    // routing table. Never fails structurally; unknown/empty input yields a
    // bundle carrying only an empty "default" profile.
    [[nodiscard]] ConfigBundle parseBundle(std::string_view content);

    // Resolve the effective Config for a profile/route key. Resolution order:
    // the profile named by routes[key]; else the "default" profile; else an
    // empty default-constructed Config. Presence of a route must be tested
    // separately via ConfigBundle::routes when "not routed" and "routed to
    // default" need to be distinguished.
    [[nodiscard]] Config selectConfig(const ConfigBundle &bundle, std::string_view key);

    // Backward-compatible single-profile entry point. Equivalent to selecting
    // the "default" profile from parseBundle(content).
    [[nodiscard]] Config parseConfig(std::string_view content);

    [[nodiscard]] bool writeConfig(int fd, const Config &config);
    [[nodiscard]] bool readConfig(int fd, Config &config);
}

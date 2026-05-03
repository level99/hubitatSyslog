/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/* Notes

2020-08-18 - staylorx
  - A couple of dumb coding errors, and still trying to sort out TCP
2020-08-18 - staylorx
  - Received version from original author (great start!)
  - Attemping RFC5424 format for syslog
  - Date/time stamping with the hub timezone

2024-01-29 - rmonk
  - Changed the logging init delay to 10 seconds to try and get it
    to properly start on boot

2024-12-10 - Sylvain Robitaille
  - "hostname" input field defaults to the hub's internal name
  - syslog facility is configurable / priority is derived from hub's
    log "level"
  - rfc5424 syslog protocol version is identified as such, rather
    than being just a magical "1"
  - jtp10181's escapeStringHTMLforMsg() method is applied to the
    incoming log message
2024-12-28 - Sylvain Robitaille
  - we differentiate between "apps" and "devs" in the logged messages
  - loop avoidance checks that the incoming message wasn't from a
    "dev" in addition to checking that its id number doesn't match our own

*/

metadata {
    definition (name: "Syslog", namespace: "hubitatuser12", author: "Hubitat User 12, staylorx, jtp10181, rmonk, Sylvain Robitaille (TheRockgarden)") {
        capability "Initialize"
    }
    command "disconnect"

    preferences {
        input("ip", "text", title: "Syslog IP Address", description: "ip address of the syslog server", required: true)
        input("port", "number", title: "Syslog IP Port", description: "syslog port", defaultValue: 514, required: true)
        input("udptcp", "enum", title: "UDP or TCP?", description: "", defaultValue: "UDP", options: ["UDP","TCP"])
        input("logFacility", "enum", title: "Log Facility", description: "", defaultValue: "local0", options: ["kern","user","mail","daemon","auth","syslog","lpr","news","uucp","cron","authpriv","ftp","ntp","security","console","local0","local1","local2","local3","local4","local5","local6","local7"])
        input("hostname", "text", title: "Hub Hostname", description: "hostname of the hub; leave empty for IP address", defaultValue: location.hub["name"])
        input("localBackoffMaxMin", "number", title: "Local logsocket reconnect backoff cap (minutes)", description: "Max time between reconnect attempts to the LOCAL Hubitat logsocket (the websocket that feeds this driver hub log events). Lower = faster recovery, more log noise during sustained outages. Higher = quieter logs, longer worst-case downtime. Schedule doubles per attempt up to this cap (1, 2, 4, 8, ... capped). Range 1-60, default 10. Note: this does NOT affect the outbound syslog destination — UDP/TCP sends to the configured Syslog IP are fire-and-forget per message, no connection retry applies.", defaultValue: 10, range: "1..60")
        input("logEnable", "bool", title: "Enable debug logging", description: "", defaultValue: false)
    }
}

import groovy.json.JsonSlurper
import hubitat.device.HubAction
import hubitat.device.Protocol

void logsOff(){
    log.warn "debug logging disabled..."
    device.updateSetting("logEnable",[value:"false",type:"bool"])
}

void installed() {
    if (logEnable) log.debug "installed()"
    updated()
}

void updated() {
    if (logEnable) log.debug "updated()"
    initialize()
    //turn off debug logs after 30 minutes
    if (logEnable) runIn(1800,logsOff)
}

void parse(String description) {

    def descData
    try {
        descData = new JsonSlurper().parseText(description)
    } catch (e) {
        // Malformed logsocket frame would otherwise crash parse() into
        // Hubitat's generic crash log with no context for which message
        // tripped it. Surface here and drop the frame.
        log.error "parse() failed to decode logsocket frame: ${e.message}; raw=${description}"
        return
    }

    // don't log our own messages, we will get into a loop
    if (descData.type == "dev" && "${descData.id}" == "${device.id}") {
        return
    }

    if (ip == null) {
        log.warn "No log server set"
        return
    }

    // Use a local variable for the effective hostname — `hostname` is a
    // preference (read-only at runtime). Fall back to the hub's local IP
    // if the preference is empty.
    def hub = location.hubs[0]
    def effectiveHostname = hostname?.trim() ?: hub.getDataValue("localIP")

    // Use a LOCAL `logLevel` (don't leak into script binding).
    def logLevel = descData.level != null ? descData.level : "info"

    // rfc5424 syslog protocol version
    def syslogVersion = 1

    // facility * 8 + severity = priority. Defensive defaults: local0 (16<<3=128)
    // for unknown facility, info (6) for unknown level — covers Hubitat
    // platform levels not in our static map (e.g. "verbose", "system").
    def facility = getFacilityMap()[logFacility] ?: getFacilityMap()["local0"]
    def severity = getPriorityMap()[logLevel] ?: 6
    def priority = facility + severity

    // we get date-space-time but would like ISO8601
    if (logEnable) log.debug "timezone from hub is ${location.timeZone?.toString()}"
    def dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    def date = Date.parse(dateFormat, descData.time)

    // location timeZone comes from the geolocation of the hub. It's possible it's not set?
    // Date.format with null timeZone falls back to JVM default — acceptable.
    def isoDate = date.format("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", location.timeZone)
    if (logEnable) log.debug "time we get = ${descData.time}; time we want ${isoDate}"

    // jtp10181
    def message = escapeStringHTMLforMsg(descData.msg)

    // RFC5424 frame: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // PROCID, MSGID, STRUCTURED-DATA all set to NILVALUE ("-") since we don't have them.
    def constructedString = "<${priority}>${syslogVersion} ${isoDate} ${effectiveHostname} " + descData.type + " " + descData.id.toString() + " - - - ${message}"
    if (logEnable) log.debug "sending: ${constructedString} to ${udptcp}:${ip}:${port}"

    if (udptcp == 'UDP') {
        if (logEnable) log.debug "UDP selected"
        sendHubCommand(new HubAction(constructedString, Protocol.LAN, [destinationAddress: "${ip}:${port}", type: HubAction.Type.LAN_TYPE_UDPCLIENT, ignoreResponse:true]))
    } else {
        if (logEnable) log.debug "TCP selected"
        sendHubCommand(new HubAction(constructedString, Protocol.RAW_LAN, [destinationAddress: "${ip}:${port}", type: HubAction.Type.LAN_TYPE_RAW]))
    }
}

void connect() {
    if (logEnable) log.debug "attempting connection"
    try {
        interfaces.webSocket.connect("http://localhost:8080/logsocket")
        pauseExecution(1000)
    } catch(e) {
        // `logger` doesn't exist in the Hubitat driver context — use log.
        log.error "connect() error: ${e.message}"
    }
}

void disconnect() {
    state.connected = false
    interfaces.webSocket.close()
}

void uninstalled() {
    disconnect()
}

void initialize() {
    if (logEnable) log.debug "initialize()"
    state.connected = false
    state.failures = 0
    state.nextAttempt = 0
    log.info "Starting log export to syslog"
    // Clear any prior runIn/schedule from a previous instance — defensive,
    // since unschedule(String) doesn't reliably match runIn(N, String) jobs
    // on current firmware (see Refs below).
    unschedule()
    runIn(10, "connect")
    // Periodic health check drives recovery from any disconnected state.
    // See "Reconnect strategy" comment block on webSocketStatus() below for
    // why reconnect logic must live here, NOT inside the status handler.
    runEvery1Minute("healthCheck")
}

// Periodic recovery driver for the LOCAL logsocket websocket.
// Runs every minute regardless of connection state. When healthy: resets
// backoff counters and exits. When down: applies exponential backoff up
// to the user-configured cap (preference localBackoffMaxMin, default
// 10 min) before each retry. Schedule per attempt: 1m, 2m, 4m, 8m, 16m,
// 32m, ... capped. Lower bound on the cap is 1 min (= no backoff
// effectively, attempts every healthCheck tick).
//
// Note: this only governs the LOCAL websocket (driver ← Hubitat
// logsocket). Outbound syslog sends to the user-configured destination
// (UDP or TCP per `udptcp`) are fire-and-forget per message — there is
// no outbound connection state to retry. A future enhancement could add
// a separate `remoteBackoffMaxMin` for an outbound TCP-keepalive mode.
void healthCheck() {
    if (state.connected == true) {
        // Healthy — reset backoff state.
        state.failures = 0
        state.nextAttempt = 0
        if (logEnable) log.debug "healthCheck: connected"
        return
    }
    if (now() < (state.nextAttempt ?: 0)) {
        // Backoff window in effect; skip this tick silently.
        if (logEnable) log.debug "healthCheck: in backoff window (next attempt at ${new Date((state.nextAttempt ?: 0) as Long)}), skipping"
        return
    }
    state.failures = (state.failures ?: 0) + 1
    def maxMin = (localBackoffMaxMin ?: 10) as Integer
    def attempt = state.failures as Integer
    // Exponential doubling: 1, 2, 4, 8, 16, 32, ... capped at maxMin.
    // Cap the shift count to avoid Integer overflow on long stuck periods.
    def shifted = (attempt > 30) ? Integer.MAX_VALUE : (1 << (attempt - 1))
    def backoffMin = Math.min(shifted, maxMin) as Integer
    state.nextAttempt = now() + (backoffMin * 60000L)
    log.warn "healthCheck: not connected (failure #${attempt}); reconnecting, next attempt in ${backoffMin}m if this also fails"
    connect()
}

void webSocketStatus(String message) {
    if (logEnable) log.debug "Got status ${message}"
    // ────────────────────────── Reconnect strategy ──────────────────────────
    // This handler ONLY updates state.connected. It does NOT schedule any
    // reconnect calls. Recovery is driven entirely by the periodic
    // healthCheck() above. Why:
    //
    //   1. Hubitat's webSocket lifecycle emits "status: closing" any time
    //      connect() is called on an already-open socket — the platform
    //      implicitly tears down the old socket BEFORE opening the new one,
    //      and the closing event for the old socket fires ~30ms before the
    //      open event for the new socket. If the status handler treats
    //      "closing" as a disconnect signal and schedules a reconnect, the
    //      result is an infinite connect → closing → reconnect loop. This
    //      was empirically observed on firmware 2.5.0.126 (C-8) — every
    //      connect cycle produced a "closing" event whether or not a real
    //      disconnect had occurred.
    //
    //   2. unschedule(String) on current firmware does NOT reliably cancel
    //      runIn(N, String) jobs. So a "cancel the watchdog when open
    //      arrives" approach doesn't work either.
    //
    //   3. The Hubitat docs themselves do not enumerate the status messages
    //      emitted by webSocketStatus — only that disconnections and errors
    //      will be reported. So any status-event-based recovery scheme is
    //      empirical and brittle.
    //
    //   4. The community-recommended pattern (multiple drivers including
    //      the Logitech Harmony driver and the Log Watchdog driver) is to
    //      pull reconnect logic OUT of webSocketStatus and put it in a
    //      periodic ping/health routine. This avoids the loop by
    //      construction.
    //
    // Refs:
    //   - https://docs2.hubitat.com/en/developer/interfaces/websocket-interface
    //   - https://community.hubitat.com/t/anyway-to-know-if-a-websocket-is-closed/44516
    //   - https://community.hubitat.com/t/unschedule-doesn-t-always-work/75532
    //
    // Status messages we observe (NOT exhaustively documented by Hubitat):
    //   "status: open"       — connected
    //   "status: closing"    — transient when we just called connect();
    //                          can also appear on a real graceful close.
    //                          Treated identically here — set state and let
    //                          healthCheck recover if needed.
    //   "status: closed"     — terminal
    //   "failure: <reason>"  — error
    //
    // Note: this is the LOCAL websocket to Hubitat's logsocket
    // (http://localhost:8080/logsocket), NOT the syslog destination. UDP
    // and TCP outbound sends are fire-and-forget per message; there is no
    // outbound "connection" to manage.
    if (message?.startsWith("status: open")) {
        state.connected = true
        log.info "logsocket websocket connected — forwarding to ${udptcp} ${ip}:${port}"
    } else if (message?.startsWith("status: closing")) {
        if (logEnable) log.debug "Got status: closing (deferred to healthCheck)"
        state.connected = false
    } else {
        // status: closed, failure: *, anything else
        log.warn "logsocket websocket lost (${message})"
        state.connected = false
    }
}

// ------------------------------------------------------------------
// 2024-08-25 jtp10181
private String escapeStringHTMLforMsg(String str) {
    if (str) {
        str = str.replaceAll("&amp;", "&")
        str = str.replaceAll("&lt;", "<")
        str = str.replaceAll("&gt;", ">")
        str = str.replaceAll("&#027;", "'")
        str = str.replaceAll("&#039;", "'") 
        str = str.replaceAll("&apos;", "'")
        str = str.replaceAll("&quot;", '"')
               str = str.replaceAll("&nbsp;", " ")
        //Strip HTML Span Tags
        str = str.replaceAll(/<\/?span.*?>/, "")
    }
    return str
}

// ------------------------------------------------------------------
// 2024-12-10 Sylvain Robitaille
private getFacilityMap() {
    [
        "kern":       (0<<3),
        "user":       (1<<3),
        "mail":       (2<<3),
        "daemon":     (3<<3),
        "auth":       (4<<3),
        "syslog":     (5<<3),
        "lpr":        (6<<3),
        "news":       (7<<3),
        "uucp":       (8<<3),
        "cron":       (9<<3),
        "authpriv":  (10<<3),
        "ftp":       (11<<3),
        "ntp":       (12<<3),
        "security":  (13<<3),
        "console":   (14<<3),
//      "unused":    (15<<3),  /* Clock/cron daemon (Solaris) */
        "local0":    (16<<3),
        "local1":    (17<<3),
        "local2":    (18<<3),
        "local3":    (19<<3),
        "local4":    (20<<3),
        "local5":    (21<<3),
        "local6":    (22<<3),
        "local7":    (23<<3),
    ]
}

private getPriorityMap() {
    [
        "emergency": 0,
        "emerg":     0,
        "panic":     0,
        "alert":     1,
        "critical":  2,
        "crit":      2,
        "error":     3,
        "err":       3,
        "warning":   4,
        "warn":      4,
        "notice":    5,
        "info":      6,
        "debug":     7,
        "trace":     7,
    ]
}


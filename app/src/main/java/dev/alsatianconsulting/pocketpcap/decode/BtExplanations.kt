package dev.alsatianconsulting.pocketpcap.decode

/**
 * Plain-language explanations for Bluetooth (HCI / L2CAP / ATT / BLE advertising)
 * protocol layers and common fields. Bluetooth captures are dense and opaque to
 * non-experts, so we annotate the decode tree with a one-line "what this means".
 *
 * Keyed by the PDML protocol/field `name` token (the same token Wireshark uses in
 * display filters, e.g. "bthci_cmd", "btatt"). Lookup is best-effort: an unknown
 * name simply returns "" and no annotation is shown.
 */
object BtExplanations {

    private val byName: Map<String, String> = mapOf(
        // Transport / framing
        "bluetooth" to "Bluetooth meta layer: which direction this packet went and over which transport (HCI H4).",
        "hci_h4" to "HCI H4: the UART framing byte that tags each packet as a command, event, or data.",
        "bthci_cmd" to "HCI Command: an instruction the phone's Bluetooth stack sent down to the controller chip (e.g. start scanning, connect).",
        "bthci_evt" to "HCI Event: a notification the controller chip sent back up to the host (e.g. connection complete, scan result).",
        "bthci_acl" to "HCI ACL Data: the actual data payload exchanged with a connected device (carries L2CAP/ATT inside).",
        "bthci_sco" to "HCI SCO Data: synchronous audio data, used for hands-free / headset voice calls.",

        // L2CAP and friends
        "btl2cap" to "L2CAP: Bluetooth's multiplexing layer — splits the link into logical channels (one per profile/service).",
        "btsdp" to "SDP (Service Discovery Protocol): how one device asks another 'what services do you offer?' (e.g. audio, file transfer).",
        "btrfcomm" to "RFCOMM: emulates a serial port over Bluetooth — used by older profiles like hands-free and serial links.",
        "btsmp" to "SMP (Security Manager): negotiates pairing, bonding and the encryption keys for a BLE link.",

        // GATT / ATT (BLE app layer)
        "btatt" to "ATT (Attribute Protocol): the request/response layer BLE devices use to read and write characteristics (battery %, heart rate, etc.).",
        "btgatt" to "GATT: the service/characteristic structure layered on ATT — how BLE data is organized.",

        // BLE advertising / link layer
        "btle" to "BLE Link Layer: the lowest level of Bluetooth Low Energy radio packets (advertising and connection events).",
        "btle_rf" to "BLE RF metadata: radio channel, signal strength (RSSI) and PHY for this low-energy packet.",
        "btcommon" to "Common Bluetooth fields shared across BLE advertising and EIR data (device name, appearance, service UUIDs).",
        "btmesh" to "Bluetooth Mesh: many-to-many networking used by smart-home / lighting devices.",

        // A few high-value individual fields
        "bthci_evt.bd_addr" to "The 48-bit hardware address (MAC) of the remote Bluetooth device.",
        "bthci_cmd.bd_addr" to "The 48-bit hardware address (MAC) of the device this command targets.",
        "btatt.handle" to "Attribute handle: a numeric pointer to one specific value (characteristic) on the remote device.",
        "btatt.opcode" to "ATT operation: read, write, notify, or indicate — what this device is doing with the attribute.",
        "btle.advertising_address" to "Advertising address: the MAC of the device broadcasting these BLE advertisements.",
        "btle.access_address" to "Access address: identifies which BLE connection these link-layer packets belong to.",
    )

    /**
     * Explanation for a node. Only the protocol/section header (e.g. "bthci_evt")
     * and a few high-value individual fields (exact matches) are annotated — we
     * deliberately do NOT fall back to the protocol family for every leaf field,
     * which would repeat the same generic line under every row and add noise.
     */
    fun lookup(name: String?): String {
        if (name.isNullOrBlank()) return ""
        return byName[name] ?: ""
    }

}

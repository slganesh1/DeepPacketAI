package diameter

// CommandCodes maps Diameter command codes to names.
var CommandCodes = map[uint32]string{
	257: "Capabilities-Exchange",  // CER/CEA
	258: "Re-Auth",               // RAR/RAA
	271: "Accounting",            // ACR/ACA
	272: "Credit-Control",        // CCR/CCA
	274: "Abort-Session",         // ASR/ASA
	275: "Session-Termination",   // STR/STA
	265: "AA",                    // AAR/AAA
	300: "User-Authorization",    // UAR/UAA
	301: "Server-Assignment",     // SAR/SAA
	302: "Location-Info",         // LIR/LIA
	303: "Multimedia-Auth",       // MAR/MAA
	304: "Registration-Termination", // RTR/RTA
	316: "Update-Location",       // ULR/ULA
	318: "Authentication-Information", // AIR/AIA
	321: "Cancel-Location",       // CLR/CLA
	323: "Notify",                // NOR/NOA
}

// ApplicationIDs maps Diameter application IDs to names.
var ApplicationIDs = map[uint32]string{
	0:          "Common Messages",
	1:          "NASREQ",
	3:          "Diameter Base Accounting",
	4:          "Credit-Control",
	16777216:   "3GPP Cx",
	16777217:   "3GPP Sh",
	16777251:   "3GPP S6a/S6d",
	16777238:   "3GPP Gx",
	16777236:   "3GPP Rx",
	16777272:   "3GPP S13",
	16777302:   "3GPP S6b",
}

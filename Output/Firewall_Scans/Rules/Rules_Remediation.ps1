# ============================================================
# TraceForge Firewall Remediation Script
# Generated: 10/18/2025 21:44:49
# Each section below corresponds to a risky rule identified.
# ============================================================

# --- Remediation for Rule: Wi-Fi Direct Spooler Use (Out)

Set-NetFirewallRule -Name 'WFDPRINT-SPOOL-Out-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (TCP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (SSDP-Out)

Set-NetFirewallRule -Name 'NETDIS-SSDPSrv-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (WSD Events-Out)

Set-NetFirewallRule -Name 'NETDIS-WSDEVNT-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Wi-Fi Direct Spooler Use (In)

Set-NetFirewallRule -Name 'WFDPRINT-SPOOL-In-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (TCP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Packet Too Big (ICMPv6-Out)



# --- Remediation for Rule: Connected Devices Platform (UDP-Out)

Set-NetFirewallRule -Name 'CDPSvc-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - IPv6 (IPv6-In)

Set-NetFirewallRule -Name 'CoreNet-IPv6-In' -LocalPort <specific_port>



# --- Remediation for Rule: Connected Devices Platform - Wi-Fi Direct Transport (TCP-Out)

Set-NetFirewallRule -Name 'CDPSvc-WFD-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: mDNS (UDP-Out)

Set-NetFirewallRule -Name 'MDNS-Out-UDP-Domain-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Delivery Optimization (UDP-In)



# --- Remediation for Rule: Core Networking - Parameter Problem (ICMPv6-Out)



# --- Remediation for Rule: Core Networking - Router Advertisement (ICMPv6-In)



# --- Remediation for Rule: Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)



# --- Remediation for Rule: Core Networking - Dynamic Host Configuration Protocol (DHCP-In)



# --- Remediation for Rule: Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)



# --- Remediation for Rule: Network Discovery for Teredo (SSDP-In)

Set-NetFirewallRule -Name 'NETDIS-SSDPSrv-In-UDP-Teredo' -LocalPort <specific_port>



# --- Remediation for Rule: Connected Devices Platform (TCP-Out)

Set-NetFirewallRule -Name 'CDPSvc-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Wi-Fi Direct Scan Service Use (In)

Set-NetFirewallRule -Name 'WFDPRINT-SCAN-In-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (PNRP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-PnrpSvc-UDP-OUT' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Router Solicitation (ICMPv6-Out)



# --- Remediation for Rule: Remote Assistance (SSDP UDP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-SSDPSrv-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (SSDP TCP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-SSDPSrv-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)



# --- Remediation for Rule: Network Discovery (UPnP-Out)

Set-NetFirewallRule -Name 'NETDIS-UPnPHost-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (RA Server TCP-In)

Set-NetFirewallRule -Name 'RemoteAssistance-RAServer-In-TCP-NoScope-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Multicast Listener Report v2 (ICMPv6-Out)



# --- Remediation for Rule: Microsoft Media Foundation Network Source IN [UDP 5004-5009]



# --- Remediation for Rule: Windows Device Management Enrollment Service (TCP out)



# --- Remediation for Rule: mDNS (UDP-Out)

Set-NetFirewallRule -Name 'MDNS-Out-UDP-Public-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Delivery Optimization (TCP-In)



# --- Remediation for Rule: Core Networking - Multicast Listener Done (ICMPv6-Out)



# --- Remediation for Rule: Windows Device Management Certificate Installer (TCP out)



# --- Remediation for Rule: Core Networking - Teredo (UDP-Out)

Set-NetFirewallRule -Name 'CoreNet-Teredo-Out' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Router Solicitation (ICMPv6-In)



# --- Remediation for Rule: Wireless Display Infrastructure Back Channel (TCP-In)



# --- Remediation for Rule: Core Networking - Group Policy (LSASS-Out)

Set-NetFirewallRule -Name 'CoreNet-GP-LSASS-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Recommended Troubleshooting Client (HTTP/HTTPS Out)

Set-NetFirewallRule -Name 'Microsoft-Windows-Troubleshooting-HTTP-HTTPS-Out' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (Pub WSD-Out)

Set-NetFirewallRule -Name 'NETDIS-FDRESPUB-WSD-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Wireless Display (TCP-Out)

Set-NetFirewallRule -Name 'WirelessDisplay-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Wireless Display (UDP-Out)

Set-NetFirewallRule -Name 'WirelessDisplay-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (RA Server TCP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-RAServer-Out-TCP-NoScope-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Router Advertisement (ICMPv6-Out)



# --- Remediation for Rule: Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)



# --- Remediation for Rule: Core Networking - IPHTTPS (TCP-Out)

Set-NetFirewallRule -Name 'CoreNet-IPHTTPS-Out' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Media Foundation Network Source IN [TCP 554]



# --- Remediation for Rule: Core Networking - Internet Group Management Protocol (IGMP-Out)

Set-NetFirewallRule -Name 'CoreNet-IGMP-Out' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Parameter Problem (ICMPv6-In)



# --- Remediation for Rule: Core Networking - DNS (UDP-Out)

Set-NetFirewallRule -Name 'CoreNet-DNS-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (NB-Datagram-Out)

Set-NetFirewallRule -Name 'NETDIS-NB_Datagram-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Teredo (UDP-In)



# --- Remediation for Rule: Microsoft Media Foundation Network Source OUT [TCP ALL]

Set-NetFirewallRule -Name 'NVS-FrameServer-Out-TCP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)



# --- Remediation for Rule: AllJoyn Router (UDP-Out)

Set-NetFirewallRule -Name 'AllJoyn-Router-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Device Management Device Enroller (TCP out)



# --- Remediation for Rule: Core Networking - Multicast Listener Query (ICMPv6-Out)



# --- Remediation for Rule: Network Discovery (LLMNR-UDP-Out)

Set-NetFirewallRule -Name 'NETDIS-LLMNR-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery for Teredo (UPnP-In)

Set-NetFirewallRule -Name 'NETDIS-UPnPHost-In-TCP-Teredo' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Time Exceeded (ICMPv6-Out)



# --- Remediation for Rule: Connected Devices Platform (UDP-In)

Set-NetFirewallRule -Name 'CDPSvc-In-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Connected Devices Platform (TCP-In)

Set-NetFirewallRule -Name 'CDPSvc-In-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: AllJoyn Router (TCP-Out)

Set-NetFirewallRule -Name 'AllJoyn-Router-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (TCP-In)

Set-NetFirewallRule -Name 'RemoteAssistance-In-TCP-EdgeScope' -LocalPort <specific_port>



# --- Remediation for Rule: Proximity sharing over TCP (TCP sharing-Out)

Set-NetFirewallRule -Name 'ProximityUxHost-Sharing-Out-TCP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Multicast Listener Report (ICMPv6-Out)



# --- Remediation for Rule: Wi-Fi Direct Network Discovery (Out)

Set-NetFirewallRule -Name 'WFDPRINT-DAFWSD-Out-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Packet Too Big (ICMPv6-In)



# --- Remediation for Rule: Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)



# --- Remediation for Rule: Core Networking - IPHTTPS (TCP-In)



# --- Remediation for Rule: AllJoyn Router (UDP-In)

Set-NetFirewallRule -Name 'AllJoyn-Router-In-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Remote Assistance (PNRP-Out)

Set-NetFirewallRule -Name 'RemoteAssistance-PnrpSvc-UDP-OUT-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Multicast Listener Done (ICMPv6-In)



# --- Remediation for Rule: Connected User Experiences and Telemetry

Set-NetFirewallRule -Name 'Microsoft-Windows-Unified-Telemetry-Client' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Destination Unreachable (ICMPv6-In)



# --- Remediation for Rule: Wi-Fi Direct Scan Service Use (Out)

Set-NetFirewallRule -Name 'WFDPRINT-SCAN-Out-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Connected Devices Platform - Wi-Fi Direct Transport (TCP-In)

Set-NetFirewallRule -Name 'CDPSvc-WFD-In-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: mDNS (UDP-Out)

Set-NetFirewallRule -Name 'MDNS-Out-UDP-Private-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)



# --- Remediation for Rule: Wi-Fi Direct Network Discovery (In)

Set-NetFirewallRule -Name 'WFDPRINT-DAFWSD-In-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Wireless Display (TCP-In)

Set-NetFirewallRule -Name 'WirelessDisplay-In-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - IPv6 (IPv6-Out)

Set-NetFirewallRule -Name 'CoreNet-IPv6-Out' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (WSD EventsSecure-Out)

Set-NetFirewallRule -Name 'NETDIS-WSDEVNTS-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Proximity sharing over TCP (TCP sharing-In)

Set-NetFirewallRule -Name 'ProximityUxHost-Sharing-In-TCP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Internet Group Management Protocol (IGMP-In)

Set-NetFirewallRule -Name 'CoreNet-IGMP-In' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Group Policy (NP-Out)

Set-NetFirewallRule -Name 'CoreNet-GP-NP-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Multicast Listener Report v2 (ICMPv6-In)



# --- Remediation for Rule: Network Discovery (WSD-Out)

Set-NetFirewallRule -Name 'NETDIS-FDPHOST-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Multicast Listener Query (ICMPv6-In)



# --- Remediation for Rule: Windows Device Management Sync Client (TCP out)



# --- Remediation for Rule: Core Networking - Multicast Listener Report (ICMPv6-In)



# --- Remediation for Rule: Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)



# --- Remediation for Rule: Core Networking - Time Exceeded (ICMPv6-In)



# --- Remediation for Rule: Remote Assistance (TCP-In)

Set-NetFirewallRule -Name 'RemoteAssistance-In-TCP-EdgeScope-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (UPnPHost-Out)

Set-NetFirewallRule -Name 'NETDIS-UPnP-Out-TCP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Network Discovery (NB-Name-Out)

Set-NetFirewallRule -Name 'NETDIS-NB_Name-Out-UDP-Active' -LocalPort <specific_port>



# --- Remediation for Rule: Core Networking - Group Policy (TCP-Out)

Set-NetFirewallRule -Name 'CoreNet-GP-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device functionality (qWave-TCP-Out)

Set-NetFirewallRule -Name 'PlayTo-QWave-Out-TCP-PlayToScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTCP-Streaming-In)

Set-NetFirewallRule -Name 'PlayTo-In-UDP-LocalSubnetScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTP-Streaming-Out)

Set-NetFirewallRule -Name 'PlayTo-Out-UDP-PlayToScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTP-Streaming-Out)

Set-NetFirewallRule -Name 'PlayTo-Out-UDP-LocalSubnetScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTCP-Streaming-In)

Set-NetFirewallRule -Name 'PlayTo-In-UDP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device functionality (qWave-UDP-Out)

Set-NetFirewallRule -Name 'PlayTo-QWave-Out-UDP-PlayToScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTP-Streaming-Out)

Set-NetFirewallRule -Name 'PlayTo-Out-UDP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: Cast to Device streaming server (RTCP-Streaming-In)

Set-NetFirewallRule -Name 'PlayTo-In-UDP-PlayToScope' -LocalPort <specific_port>



# --- Remediation for Rule: Email and accounts

Set-NetFirewallRule -Name 'Microsoft.AccountsControl_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Desktop App Web Viewer

Set-NetFirewallRule -Name 'Microsoft.Win32WebViewHost_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Desktop App Web Viewer

Set-NetFirewallRule -Name 'Microsoft.Win32WebViewHost_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Defender SmartScreen

Set-NetFirewallRule -Name 'Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Your account

Set-NetFirewallRule -Name 'Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Your account

Set-NetFirewallRule -Name 'Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Content

Set-NetFirewallRule -Name 'Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Family Safety

Set-NetFirewallRule -Name 'Microsoft.Windows.ParentalControls_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Shell Experience

Set-NetFirewallRule -Name 'Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Print Queue

Set-NetFirewallRule -Name 'Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Xbox Game UI

Set-NetFirewallRule -Name 'Microsoft.XboxGameCallableUI_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.Client.AIX_1000.26100.29.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.AIX/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.AIX_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.Search_1000.26100.1742.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.Search/Resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.Search_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.Search_1000.26100.1742.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.Search/Resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.Search_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: NcsiUwpApp

Set-NetFirewallRule -Name 'NcsiUwpApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Print

Set-NetFirewallRule -Name 'Windows.PrintDialog_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Teams

Set-NetFirewallRule -Name '{2D8E8393-BB90-42EB-8150-7345A68A8EE5}' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Teams

Set-NetFirewallRule -Name '{A1F7A35C-F31F-4DA6-8A2E-E0DC64E4E6BA}' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.AccountsService_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.AccountsService/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.AccountsService_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.DesktopSpotlight_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.DesktopSpotlight/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.DesktopSpotlight_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.DesktopSpotlight_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.DesktopSpotlight/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.DesktopSpotlight_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.IrisService_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.IrisService/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.IrisService_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.RulesEngine_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.RulesEngine/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.RulesEngine_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.SpeechRuntime_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.SpeechRuntime/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.SpeechRuntime_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.LKG.TwinSxS_1000.26100.2894.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.LKG.TwinSxS/resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.LKG.TwinSxS_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{Microsoft.XboxGamingOverlay_2.624.1111.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.XboxGamingOverlay/resources/GameBar}

Set-NetFirewallRule -Name 'Microsoft.XboxGamingOverlay_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{Microsoft.XboxGamingOverlay_2.624.1111.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.XboxGamingOverlay/resources/GameBar}

Set-NetFirewallRule -Name 'Microsoft.XboxGamingOverlay_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Narrator

Set-NetFirewallRule -Name 'Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft 365 (Office)

Set-NetFirewallRule -Name 'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Edge Game Assist

Set-NetFirewallRule -Name 'Microsoft.Edge.GameAssist_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Xbox TCUI

Set-NetFirewallRule -Name 'Microsoft.Xbox.TCUI_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Calculator

Set-NetFirewallRule -Name 'Microsoft.WindowsCalculator_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft To Do

Set-NetFirewallRule -Name 'Microsoft.Todos_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft To Do

Set-NetFirewallRule -Name 'Microsoft.Todos_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Security

Set-NetFirewallRule -Name 'Microsoft.SecHealthUI_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Security

Set-NetFirewallRule -Name 'Microsoft.SecHealthUI_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Xbox Identity Provider

Set-NetFirewallRule -Name 'Microsoft.XboxIdentityProvider_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Family

Set-NetFirewallRule -Name 'MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: News

Set-NetFirewallRule -Name 'Microsoft.BingNews_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Work or school account

Set-NetFirewallRule -Name 'Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Work or school account

Set-NetFirewallRule -Name 'Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Default Lock Screen

Set-NetFirewallRule -Name 'Microsoft.LockApp_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Captive Portal Flow

Set-NetFirewallRule -Name 'Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.56978801.Voiess_1000.26100.4351.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.56978801.Voiess/Resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.56978801.Voiess_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.57058570.Speion_1000.26100.4351.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.57058570.Speion/Resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.57058570.Speion_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: @{MicrosoftWindows.57074914.Livtop_1000.26100.4351.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.57074914.Livtop/Resources/ProductPkgDisplayName}

Set-NetFirewallRule -Name 'MicrosoftWindows.57074914.Livtop_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (NB-Datagram-Out)

Set-NetFirewallRule -Name 'FPS-NB_Datagram-Out-UDP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (NB-Name-Out)

Set-NetFirewallRule -Name 'FPS-NB_Name-Out-UDP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (SMB-Out)

Set-NetFirewallRule -Name 'FPS-SMB-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (SMB-Out)

Set-NetFirewallRule -Name 'FPS-SMB-Out-TCP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: WFD ASP Coordination Protocol (UDP-Out)



# --- Remediation for Rule: File and Printer Sharing (NB-Session-Out)

Set-NetFirewallRule -Name 'FPS-NB_Session-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: WFD Driver-only (TCP-In)

Set-NetFirewallRule -Name 'WiFiDirect-KM-Driver-In-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: WFD Driver-only (UDP-In)

Set-NetFirewallRule -Name 'WiFiDirect-KM-Driver-In-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (NB-Datagram-Out)

Set-NetFirewallRule -Name 'FPS-NB_Datagram-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: WFD Driver-only (TCP-Out)

Set-NetFirewallRule -Name 'WiFiDirect-KM-Driver-Out-TCP' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (NB-Session-Out)

Set-NetFirewallRule -Name 'FPS-NB_Session-Out-TCP-NoScope' -LocalPort <specific_port>



# --- Remediation for Rule: WFD Driver-only (UDP-Out)

Set-NetFirewallRule -Name 'WiFiDirect-KM-Driver-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: WFD ASP Coordination Protocol (UDP-In)



# --- Remediation for Rule: File and Printer Sharing (NB-Name-Out)

Set-NetFirewallRule -Name 'FPS-NB_Name-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: File and Printer Sharing (LLMNR-UDP-In)



# --- Remediation for Rule: File and Printer Sharing (LLMNR-UDP-Out)

Set-NetFirewallRule -Name 'FPS-LLMNR-Out-UDP' -LocalPort <specific_port>



# --- Remediation for Rule: Apache HTTP Server

Set-NetFirewallRule -Name 'TCP Query User{E34BADDA-152B-4C17-9D4D-01A7AF05D833}C:\xampp\apache\bin\httpd.exe' -LocalPort <specific_port>



# --- Remediation for Rule: Apache HTTP Server

Set-NetFirewallRule -Name 'UDP Query User{EDC35D12-BC08-4AFB-B2CE-2864EB92E36A}C:\xampp\apache\bin\httpd.exe' -LocalPort <specific_port>



# --- Remediation for Rule: mysqld

Set-NetFirewallRule -Name 'TCP Query User{7F976F4C-D562-430A-9DCC-734FB3D537B6}C:\xampp\mysql\bin\mysqld.exe' -LocalPort <specific_port>



# --- Remediation for Rule: mysqld

Set-NetFirewallRule -Name 'UDP Query User{155F6C1D-CB60-44E7-B553-F1BB349EDD6D}C:\xampp\mysql\bin\mysqld.exe' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Camera

Set-NetFirewallRule -Name 'Microsoft.WindowsCamera_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Camera

Set-NetFirewallRule -Name 'Microsoft.WindowsCamera_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Web Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Feedback Hub

Set-NetFirewallRule -Name 'Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Feedback Hub

Set-NetFirewallRule -Name 'Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Allow FTP Server



# --- Remediation for Rule: Start

Set-NetFirewallRule -Name 'Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Start

Set-NetFirewallRule -Name 'Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.54792954.Filons_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Click to Do

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.Core_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.Core_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.FileExp_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.OOBE_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.OOBE_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.Photon_cw5n1h2txyewy-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Feature Experience Pack

Set-NetFirewallRule -Name 'MicrosoftWindows.Client.Photon_cw5n1h2txyewy-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Widgets Platform Runtime

Set-NetFirewallRule -Name 'Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Solitaire & Casual Games

Set-NetFirewallRule -Name 'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Solitaire & Casual Games

Set-NetFirewallRule -Name 'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Media Player

Set-NetFirewallRule -Name 'Microsoft.ZuneMusic_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Media Player

Set-NetFirewallRule -Name 'Microsoft.ZuneMusic_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Edge (mDNS-In)



# --- Remediation for Rule: App Installer

Set-NetFirewallRule -Name 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: App Installer

Set-NetFirewallRule -Name 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Google Chrome (mDNS-In)



# --- Remediation for Rule: Microsoft Edge (mDNS-In)



# --- Remediation for Rule: Microsoft Edge (mDNS-In)



# --- Remediation for Rule: Start Experiences App

Set-NetFirewallRule -Name 'Microsoft.StartExperiencesApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Get Help

Set-NetFirewallRule -Name 'Microsoft.GetHelp_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Windows Terminal

Set-NetFirewallRule -Name 'Microsoft.WindowsTerminal_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: MSN Weather

Set-NetFirewallRule -Name 'Microsoft.BingWeather_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: MSN Weather

Set-NetFirewallRule -Name 'Microsoft.BingWeather_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Xbox

Set-NetFirewallRule -Name 'Microsoft.GamingApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Xbox

Set-NetFirewallRule -Name 'Microsoft.GamingApp_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Store Experience Host

Set-NetFirewallRule -Name 'Microsoft.StorePurchaseApp_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Store Experience Host

Set-NetFirewallRule -Name 'Microsoft.StorePurchaseApp_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Clipchamp

Set-NetFirewallRule -Name 'Clipchamp.Clipchamp_yxz26nhyzhsrt-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Store

Set-NetFirewallRule -Name 'Microsoft.WindowsStore_8wekyb3d8bbwe-Out-Allow-AllCapabilities' -LocalPort <specific_port>



# --- Remediation for Rule: Microsoft Store

Set-NetFirewallRule -Name 'Microsoft.WindowsStore_8wekyb3d8bbwe-In-Allow-ServerCapability' -LocalPort <specific_port>




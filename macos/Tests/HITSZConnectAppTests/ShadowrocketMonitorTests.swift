import Foundation
import Testing
@testable import HITSZConnectApp

@Test func connectedStatusIgnoresDisconnectedCountInExtendedStatus() {
    let output = """
    Connected
    Extended Status <dictionary> {
      DisconnectedCount : 3
      Status : 2
    }
    """
    #expect(ShadowrocketMonitor.parseState(output) == .connected)
}

@Test func discoversShadowrocketServiceByProviderIdentifier() {
    let output = """
    Available network connection services in the current set (*=enabled):
    * (Connected) F8322D9E-E617-4064-8564-0A704D04F3BD VPN (com.liguangming.Shadowrocket) "Shadowrocket" [VPN:com.liguangming.Shadowrocket]
    """
    let service = ShadowrocketMonitor.shadowrocketService(from: output)
    #expect(service?.identifier == "F8322D9E-E617-4064-8564-0A704D04F3BD")
    #expect(service?.name == "Shadowrocket")
}

@Test func prefersActiveShadowrocketService() {
    let output = """
    * (Disconnected) 11111111-1111-1111-1111-111111111111 VPN (com.liguangming.Shadowrocket) "Old Shadowrocket" [VPN:com.liguangming.Shadowrocket]
    * (Connecting) 22222222-2222-2222-2222-222222222222 VPN (com.liguangming.Shadowrocket) "Active Shadowrocket" [VPN:com.liguangming.Shadowrocket]
    """
    let service = ShadowrocketMonitor.shadowrocketService(from: output)
    #expect(service?.identifier == "22222222-2222-2222-2222-222222222222")
    #expect(service?.name == "Active Shadowrocket")
}

@Test func findsOnlyRunningShadowrocketInterface() {
    let output = """
    utun5: flags=8050<POINTOPOINT,RUNNING,MULTICAST> mtu 1500
        agent domain:NetworkExtension type:VPN flags:0x3 desc:"VPN: Shadowrocket"
    utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
        agent domain:NetworkExtension type:VPN flags:0x3 desc:"VPN: Shadowrocket"
    """
    #expect(ShadowrocketMonitor.shadowrocketInterface(from: output) == "utun6")
}

@Test func onlyConnectedOrConnectingStateIsRestoredAfterBootstrap() {
    #expect(ShadowrocketConnectionState.connected.shouldRestoreAfterBootstrap)
    #expect(ShadowrocketConnectionState.connecting.shouldRestoreAfterBootstrap)
    #expect(!ShadowrocketConnectionState.disconnecting.shouldRestoreAfterBootstrap)
    #expect(!ShadowrocketConnectionState.disconnected.shouldRestoreAfterBootstrap)
}

@Test func bridgeConfigDefaultsToSystemRouting() {
    #expect(!BridgeConnectionConfig().autoDetectInterface)
}

@Test func appBridgeNormalizesRegressedUnderlayAndShadowrocketSettings() {
    var saved = BridgeConnectionConfig()
    saved.autoDetectInterface = true
    saved.shadowrocket = "connect"
    saved.shadowrocketUpdateSubs = true
    saved.shadowrocketDisconnectOnExit = true

    let runtime = saved.preparedForAppBridge()
    #expect(!runtime.autoDetectInterface)
    #expect(runtime.shadowrocket == "off")
    #expect(!runtime.shadowrocketUpdateSubs)
    #expect(!runtime.shadowrocketDisconnectOnExit)

    // Preparing a runtime copy must not mutate the encrypted profile model.
    #expect(saved.autoDetectInterface)
    #expect(saved.shadowrocket == "connect")
}

@Test func shadowrocketURLFallbackIsHiddenAndBackgroundOnly() {
    #expect(ShadowrocketMonitor.shadowrocketBundleArguments() == [
        "-g", "-j", "-b", "com.liguangming.Shadowrocket"
    ])
    #expect(ShadowrocketMonitor.shadowrocketURLArguments("connect") == [
        "-g", "-j", "shadowrocket://connect"
    ])
}

@Test func bridgeErrorFieldIsDecoded() {
    let line = Data(#"{"type":"error","state":"error","message":"failed","error":"root cause"}"#.utf8)
    #expect(BridgeInboundEvent.decode(line: line)?.error == "root cause")
}

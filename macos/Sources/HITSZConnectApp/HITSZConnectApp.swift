import AppKit
import SwiftUI

final class HITSZConnectApplicationDelegate: NSObject, NSApplicationDelegate {
    weak var state: AppState?

    func applicationWillTerminate(_ notification: Notification) {
        state?.shutdown()
    }
}

@main
struct HITSZConnectApp: App {
    @NSApplicationDelegateAdaptor(HITSZConnectApplicationDelegate.self) private var appDelegate
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup("HITSZ Connect") {
            ContentView()
                .environmentObject(state)
                .onAppear {
                    appDelegate.state = state
                }
                .frame(minWidth: 720, minHeight: 520)
        }

        MenuBarExtra("HITSZ Connect", systemImage: state.phase.systemImage) {
            StatusMenuView()
                .environmentObject(state)
        }
        // A native menu keeps the status item compact and gives connection
        // actions proper macOS keyboard/menu behavior instead of presenting a
        // second custom floating window.
        .menuBarExtraStyle(.menu)
    }
}

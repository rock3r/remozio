import Darwin
import Foundation
import RemozioMach

/// Keeps each looked-up right alive. Only the subsequent handshake can authenticate the authority.
final class CommandFrontendEndpoint {
    private let serviceName: String
    private var current: MachCommandAuthorityPort?
    init(serviceName: String) throws {
        guard !serviceName.utf8.contains(0), !serviceName.isEmpty,
              serviceName.utf8.count < remozio_frontend_service_name_capacity() else {
            throw CommandFrontendConfigurationError.invalidConfiguration
        }
        self.serviceName = serviceName
    }
    func lookup() throws -> mach_port_t {
        var port: mach_port_t = 0, unavailable = false
        let status = serviceName.withCString { remozio_frontend_lookup_service($0, &port, &unavailable) }
        guard status == KERN_SUCCESS else {
            if unavailable { throw CommandAuthorityEndpointError.unavailable }
            throw MachCommandCallerError.mach(status)
        }
        defer { if port != MACH_PORT_NULL { _ = mach_port_deallocate(mach_task_self_, port) } }
        let retained = try MachCommandAuthorityPort(copying: port)
        current?.close(); current = retained
        return try retained.borrowed()
    }
    func close() { current?.close(); current = nil }
    deinit { close() }
}

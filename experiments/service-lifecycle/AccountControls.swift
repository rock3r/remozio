import Darwin
import Foundation

@main struct AccountControls {
    static func main() throws {
        let own = getuid()
        guard own != 0 else { throw ServiceProbeError.account }
        let other: uid_t = own == 601 ? 602 : 601
        let valid = ServiceProbeTransportAccount(uid: other, gid: 601, groups: [601])
        try valid.validate(invokingUID: own)
        try valid.validate()
        let invalid: [(uid_t, gid_t, [gid_t], uid_t)] = [
            (0, 601, [601], own), (own, 601, [601], own), (UInt32.max, 601, [601], own),
            (other, UInt32.max, [601], own), (other, 601, [], own), (other, 601, [602], own),
            (other, 601, [601, 601], own), (other, 601, [602, 601], own),
            (other, 601, [0, 601], own), (other, 601, [80, 601], own),
            (other, 601, [601, UInt32.max], own), (other, 601, [601], 0),
            (other, 601, [601], UInt32.max),
        ]
        for (uid, gid, groups, invoker) in invalid {
            do {
                try ServiceProbeTransportAccount(uid: uid, gid: gid, groups: groups).validate(invokingUID: invoker)
                fatalError("Invalid account accepted")
            } catch ServiceProbeError.account {}
        }
        print("Synthetic account controls passed: 2 valid and 13 refused. No OS account created or service operation attempted.")
    }
}

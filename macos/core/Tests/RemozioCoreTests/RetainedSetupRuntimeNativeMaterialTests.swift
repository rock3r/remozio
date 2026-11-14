import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned machines prove closure and callback budgets. These tests cannot supply native authority or hardware proof.
final class RetainedSetupRuntimeNativeMaterialTests: XCTestCase {
    private typealias Provider = MachineUpdateRetainedSetupRuntimeNativeMaterial
    private enum Fault: Error { case custody, prepare }
    func testOneActualMachineClosesOnSuccessAndEveryOpenedRefusal() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(hasReference: true) { f in
            for scenario in 0...5 {
                let machine = try f.machine()
                let expected = try machine.retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
                var opens = 0, custody = 0, preparations = 0
                func run() throws -> RuntimePreparationState {
                    try Provider.withMachine(expected: expected, candidate: f.candidate, verifyCustody: {
                        custody += 1; try f.directory.validate()
                        if scenario == 1 || scenario == 3 && custody == 2 { throw Fault.custody }
                    }, openMachine: { opens += 1; return machine }) { actual in
                        preparations += 1; XCTAssertTrue(actual === machine)
                        if scenario == 2 { throw Fault.prepare }
                        if scenario == 4 { return .init(reference: expected.runtime.state.reference, configurationPublished: true) }
                        if scenario == 5 { return .init(reference: nil, configurationPublished: false) }
                        return expected.runtime.state
                    }
                }
                if scenario == 0 { XCTAssertEqual(try run(), expected.runtime.state) }
                else { XCTAssertThrowsError(try run()) }
                XCTAssertEqual(opens, scenario == 1 ? 0 : 1)
                XCTAssertEqual(preparations, scenario == 1 ? 0 : 1)
                XCTAssertEqual(custody, scenario == 1 || scenario == 2 ? 1 : 2)
                if opens == 0 { XCTAssertNoThrow(try machine.validateStorageLease()) }
                else {
                    XCTAssertThrowsError(try machine.validateStorageLease()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
                    try f.reopen(nil)
                }
                try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate).requireSame(as: expected)
            }
        }
    }
    func testMaterialOwnerBorrowsActualFramesAndRetainsBeforeClosingItsOnlyMachine() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let machine = try f.machine()
            let expected = try machine.retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            var opens = 0, custody = 0, preparations = 0, storageFrames = 0
            let result = try Provider.withMachine(expected: expected, candidate: f.candidate,
                verifyCustody: { custody += 1; try f.directory.validate() }, openMachine: { opens += 1; return machine }) { actual in
                    preparations += 1
                    return try MachineUpdateRetainedSetupMaterialPreparation.prepare(machine: actual, expected: expected,
                        candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                        verifyCurrent: { frame in
                            try frame.runtime.setup.requireOwner(f.owner)
                            if frame.runtime.state.reference == nil { try frame.requireSame(as: expected) }
                            else { try frame.requireRetained(f.material.reference, from: expected) }
                        }, verifyServices: { try $0.validate(account: expected.runtime.preparation) }, verifyAuthority: { _ in },
                        restoreMaterial: { _, previous, scope in
                            XCTAssertNil(previous); try scope.verify(); return f.material
                        }, validateMaterial: { material, scope in
                            try scope.verify(); XCTAssertEqual(try material.reference, try f.material.reference)
                        }, didStorageStage: { _, scope in storageFrames += 1; try scope.verify() })
                }
            XCTAssertEqual(opens, 1); XCTAssertEqual(preparations, 1); XCTAssertEqual(custody, 2); XCTAssertEqual(storageFrames, 4)
            XCTAssertEqual(result.reference, try f.material.reference); XCTAssertFalse(result.configurationPublished)
            XCTAssertThrowsError(try machine.validateStorageLease()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil)
            let actual = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            XCTAssertEqual(actual.runtime.state, result); try actual.requireRetained(f.material.reference, from: expected)
        }
    }
}

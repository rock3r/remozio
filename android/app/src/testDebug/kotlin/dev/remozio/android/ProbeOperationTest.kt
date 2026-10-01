package dev.remozio.android

import org.junit.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProbeOperationTest {
    @Test fun stoppedOperationCannotCompleteOrOwnReplacement() {
        val gate = ProbeOperation()
        val stopped = gate.begin()
        gate.invalidate()
        assertFalse(gate.complete(stopped))
        val replacement = gate.begin()
        assertFalse(gate.owns(stopped))
        assertFalse(gate.complete(stopped))
        assertTrue(gate.complete(replacement))
        assertFalse(gate.complete(replacement))
    }
    @Test fun newOperationInvalidatesPriorCallback() {
        val gate = ProbeOperation()
        val old = gate.begin()
        val current = gate.begin()
        assertFalse(gate.complete(old))
        assertTrue(gate.owns(current))
    }
}

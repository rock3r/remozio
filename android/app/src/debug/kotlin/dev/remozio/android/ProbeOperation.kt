package dev.remozio.android

/** Main-thread operation ownership. A stopped screen cannot accept an old callback. */
internal class ProbeOperation {
    private var current: Any? = null
    fun begin(): Any = Any().also { current = it }
    fun owns(token: Any): Boolean = current === token
    fun invalidate() { current = null }
    fun complete(token: Any): Boolean {
        if (!owns(token)) return false
        invalidate()
        return true
    }
}

package com.mahbub.detectvirtualdevicekmp

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform
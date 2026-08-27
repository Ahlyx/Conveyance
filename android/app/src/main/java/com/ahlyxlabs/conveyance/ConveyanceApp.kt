package com.ahlyxlabs.conveyance

import android.app.Application
import dagger.hilt.android.HiltAndroidApp

/**
 * Application entry point.
 *
 * `@HiltAndroidApp` establishes the DI container now, in Phase 10.0, so
 * later sub-phases add bindings (crypto, storage, BLE, session) without
 * re-plumbing. There are deliberately no Hilt modules yet -- an empty
 * graph is correct for a scaffold, not a stub.
 */
@HiltAndroidApp
class ConveyanceApp : Application()

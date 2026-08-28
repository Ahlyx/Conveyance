package com.ahlyxlabs.conveyance

import android.app.Application
import dagger.hilt.android.HiltAndroidApp

/**
 * Application entry point.
 *
 * `@HiltAndroidApp` establishes the DI container. Modules live with their
 * feature packages (`crypto/di`, `storage/di`); this class carries no
 * per-phase wiring of its own.
 */
@HiltAndroidApp
class ConveyanceApp : Application()

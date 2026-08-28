package com.ahlyxlabs.conveyance

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner
import dagger.hilt.android.testing.HiltTestApplication

/**
 * Swaps in [HiltTestApplication] for instrumented tests so `@HiltAndroidTest`
 * classes can inject from the real `SingletonComponent` graph. Non-Hilt
 * instrumented tests are unaffected — they never touch the Application.
 */
class HiltTestRunner : AndroidJUnitRunner() {
    override fun newApplication(
        cl: ClassLoader?,
        className: String?,
        context: Context?,
    ): Application = super.newApplication(cl, HiltTestApplication::class.java.name, context)
}

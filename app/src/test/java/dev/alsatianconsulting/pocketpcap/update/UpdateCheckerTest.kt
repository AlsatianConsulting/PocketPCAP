package dev.alsatianconsulting.pocketpcap.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {
    @Test
    fun parsesProductionReleaseResponse() {
        val release = UpdateChecker.parseLatestRelease(
            """{"tag_name":"v1.2.3","html_url":"https://github.com/AlsatianConsulting/PocketPCAP/releases/tag/v1.2.3"}"""
        )
        assertEquals("1.2.3", release.version)
        assertEquals("https://github.com/AlsatianConsulting/PocketPCAP/releases/tag/v1.2.3", release.url)
    }

    @Test
    fun comparesNumericVersionsAndPrereleases() {
        assertTrue(UpdateChecker.compareVersions("1.10.0", "1.9.9") > 0)
        assertTrue(UpdateChecker.compareVersions("1.0.0", "1.0.0-debug") > 0)
        assertTrue(UpdateChecker.compareVersions("0.2.0", "0.1.9") > 0)
        assertEquals(0, UpdateChecker.compareVersions("v1.2", "1.2.0"))
    }

    /**
     * The update check must point at the public release repository. It used to name
     * PocketPCAP-dev, which is private and has no releases, so every check failed and
     * the request disclosed a private repository name. This test pins the public one.
     */
    @Test
    fun usesThePublicReleaseRepository() {
        assertEquals("AlsatianConsulting/PocketPCAP", UpdateChecker.REPOSITORY)
        assertEquals(
            "https://api.github.com/repos/AlsatianConsulting/PocketPCAP/releases/latest",
            UpdateChecker.API_URL,
        )
        assertFalse("must not point at the private dev repository",
            UpdateChecker.REPOSITORY.endsWith("-dev"))
    }
}

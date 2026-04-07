package com.yourvpndead.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.UserManager
import com.yourvpndead.model.ProfileInfo
import com.yourvpndead.model.VpnInfo
import java.net.NetworkInterface

/**
 * Детектор рабочего профиля, VPN, и сетевых интерфейсов.
 *
 * Определяет: работает ли приложение в Work Profile / Knox / Shelter / Island,
 * активен ли VPN, какие сетевые интерфейсы присутствуют.
 *
 * Демонстрирует: что шпионское ПО может узнать об окружении пользователя
 * без root и с минимальными разрешениями.
 */
class ProfileDetector(private val context: Context) {

    /** Собрать информацию о профиле и окружении */
    fun detect(): ProfileInfo {
        val userManager = context.getSystemService(Context.USER_SERVICE) as? UserManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

        return ProfileInfo(
            // Work Profile
            isManagedProfile = detectManagedProfile(userManager),
            profileCount = userManager?.userProfiles?.size ?: 1,
            currentUserId = getCurrentUserId(),
            isDeviceOwner = dpm?.isDeviceOwnerApp(context.packageName) ?: false,
            isProfileOwner = dpm?.isProfileOwnerApp(context.packageName) ?: false,

            // Isolation apps
            hasShelter = isAppInstalled("net.typeblog.shelter"),
            hasIsland = isAppInstalled("com.oasisfeng.island"),
            hasInsular = isAppInstalled("com.oasisfeng.island.fdroid"),
            hasKnox = isAppInstalled("com.samsung.knox.securefolder")
                    || isAppInstalled("com.sec.android.app.SecondaryLockScreen"),

            // VPN
            vpn = detectVPN(),

            // Network interfaces
            interfaces = enumerateInterfaces()
        )
    }

    /** API 30+: UserManager.isManagedProfile() */
    private fun detectManagedProfile(userManager: UserManager?): Boolean {
        if (userManager == null) return false
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            userManager.isManagedProfile
        } else {
            // Fallback: UID > 100000 = secondary user (work profile)
            android.os.Process.myUid() / 100000 > 0
        }
    }

    /** User ID from UID: UID = userId * 100000 + appId */
    private fun getCurrentUserId(): Int {
        return android.os.Process.myUid() / 100000
    }

    /** Проверить установлено ли приложение */
    private fun isAppInstalled(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    /** Комплексная детекция VPN */
    private fun detectVPN(): VpnInfo {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val network = cm?.activeNetwork
        val caps = network?.let { cm.getNetworkCapabilities(it) }

        val transportVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
        val tunInterfaces = findTunInterfaces()

        return VpnInfo(
            isActiveByTransport = transportVpn,
            isActiveByInterface = tunInterfaces.isNotEmpty(),
            tunInterfaces = tunInterfaces,
            transportTypes = buildTransportList(caps)
        )
    }

    /** Найти TUN-интерфейсы (tun0, tun1, ppp0, ...) */
    private fun findTunInterfaces(): List<String> {
        return try {
            NetworkInterface.getNetworkInterfaces()?.asSequence()
                ?.filter { iface ->
                    val name = iface.name.lowercase()
                    iface.isUp && (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp"))
                }
                ?.map { it.name }
                ?.toList() ?: emptyList()
        } catch (_: Exception) { emptyList() }
    }

    /** Перечислить все сетевые интерфейсы с деталями */
    private fun enumerateInterfaces(): List<InterfaceInfo> {
        return try {
            NetworkInterface.getNetworkInterfaces()?.asSequence()?.map { iface ->
                InterfaceInfo(
                    name = iface.name,
                    displayName = iface.displayName,
                    isUp = iface.isUp,
                    isLoopback = iface.isLoopback,
                    isVirtual = iface.isVirtual,
                    ips = iface.inetAddresses.asSequence()
                        .mapNotNull { it.hostAddress?.split("%")?.first() }
                        .toList(),
                    mtu = try { iface.mtu } catch (_: Exception) { 0 }
                )
            }?.toList() ?: emptyList()
        } catch (_: Exception) { emptyList() }
    }

    private fun buildTransportList(caps: NetworkCapabilities?): List<String> {
        if (caps == null) return emptyList()
        val list = mutableListOf<String>()
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) list.add("VPN")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) list.add("WiFi")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) list.add("Cellular")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) list.add("Ethernet")
        return list
    }

    data class InterfaceInfo(
        val name: String,
        val displayName: String,
        val isUp: Boolean,
        val isLoopback: Boolean,
        val isVirtual: Boolean,
        val ips: List<String>,
        val mtu: Int
    )
}

package net.mosaic.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

public final class TunnelService extends VpnService {
    private final ScheduledExecutorService work = Executors.newSingleThreadScheduledExecutor();
    private final java.util.concurrent.ExecutorService reader = Executors.newSingleThreadExecutor();
    private volatile long handle;
    private ParcelFileDescriptor tunnel;
    private FileOutputStream output;
    private ConnectivityManager connectivity;
    private Network underlying;
    private boolean configuring;
    private final Map<Network, NetworkCapabilities> networks = new LinkedHashMap<>();
    private final ConnectivityManager.NetworkCallback changes = new ConnectivityManager.NetworkCallback() {
        @Override public void onLost(Network network) { work.execute(() -> { networks.remove(network); choosePath(); }); }
        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) { work.execute(() -> { networks.put(network, capabilities); choosePath(); }); }
    };

    @Override public void onCreate() {
        super.onCreate();
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(new NotificationChannel("connection", "Mosaic connection", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        startForeground(1, new Notification.Builder(this, "connection").setContentTitle("Mosaic").setContentText("Protected VPN connection")
            .setSmallIcon(android.R.drawable.stat_sys_warning).setContentIntent(open).setOngoing(true).build());
        connectivity = getSystemService(ConnectivityManager.class);
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), changes);
        work.scheduleWithFixedDelay(() -> poll(), 0, 10, TimeUnit.MILLISECONDS);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "disconnect".equals(intent.getAction())) {
            getSharedPreferences("mosaic", MODE_PRIVATE).edit().putBoolean("connected", false).apply();
            work.execute(() -> { closeTunnel(); message("Disconnected. Turn off Android Always-on VPN and Block connections without VPN to restore ordinary networking."); stopSelf(); });
            return START_NOT_STICKY;
        }
        work.execute(() -> {
            if (handle != 0) { return; }
            if (!isAlwaysOn() || !isLockdownEnabled()) {
                message("Enable Always-on VPN and Block connections without VPN in Android VPN settings before connecting.");
                return;
            }
            try {
                byte[] profile = ProfileStore.load(this);
                handle = Native.start(profile, getCacheDir().getAbsolutePath());
                java.util.Arrays.fill(profile, (byte) 0);
                if (handle == 0) { throw new Exception("Invalid configuration"); }
                getSharedPreferences("mosaic", MODE_PRIVATE).edit().putBoolean("connected", true).apply();
                choosePath();
            } catch (Exception error) { message("Connection failed. Import a valid configuration; Android protection remains active."); }
        });
        return START_STICKY;
    }

    private void choosePath() {
        Network selected = null;
        for (Map.Entry<Network, NetworkCapabilities> entry : networks.entrySet()) {
            NetworkCapabilities capabilities = entry.getValue();
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) { continue; }
            if (selected == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) { selected = entry.getKey(); }
        }
        if (java.util.Objects.equals(selected, underlying)) { return; }
        underlying = selected;
        setUnderlyingNetworks(selected == null ? new Network[0] : new Network[] {selected});
        if (handle != 0) { Native.pathChanged(handle); }
    }

    private void poll() {
        if (handle == 0) { return; }
        try {
            int socket = Native.socket(handle);
            if (socket >= 0 && underlying != null) {
                Native.socketReady(handle, socket, protect(socket) && Native.bindNetwork(socket, underlying.getNetworkHandle()));
            }
            if (Native.needsNetwork(handle) && !configuring) {
                configuring = true;
                JSONObject settings = new JSONObject(Native.settings(handle));
                Builder builder = new Builder().setSession("Mosaic").setMtu(1100).setBlocking(true)
                    .addAddress(settings.getString("address"), 30).addRoute("0.0.0.0", 0).addDnsServer("1.1.1.1");
                tunnel = builder.establish();
                if (tunnel == null) { throw new Exception("VPN permission unavailable"); }
                output = new FileOutputStream(tunnel.getFileDescriptor());
                Native.networkReady(handle, true);
                final ParcelFileDescriptor descriptor = tunnel;
                final long connection = handle;
                reader.execute(() -> {
                    try {
                        FileInputStream input = new FileInputStream(descriptor.getFileDescriptor());
                        byte[] packet = new byte[1101];
                        while (handle == connection) {
                            int count = input.read(packet);
                            if (count <= 0) { throw new java.io.IOException("Tunnel reader stopped"); }
                            Native.writePacket(connection, packet, count);
                        }
                    } catch (Exception error) {
                        if (handle == connection) { Native.networkReady(connection, false); message("Tunnel packet access failed; Android protection remains active. Disconnect and reconnect Mosaic."); }
                    }
                });
            }
            if (output != null) {
                byte[] packet = new byte[1100];
                for (int i = 0; i < 256; i++) {
                    int count = Native.readPacket(handle, packet);
                    if (count <= 0) { break; }
                    output.write(packet, 0, count);
                }
            }
            message(Native.status(handle));
        } catch (Exception error) {
            Native.networkReady(handle, false);
            message("Native networking failed; Android protection remains active. Disconnect and reconnect Mosaic.");
        }
    }

    private void message(String message) {
        if (!message.equals(getSharedPreferences("mosaic", MODE_PRIVATE).getString("status", ""))) {
            getSharedPreferences("mosaic", MODE_PRIVATE).edit().putString("status", message).apply();
        }
    }

    private void closeTunnel() {
        long previous = handle;
        handle = 0;
        Native.stop(previous);
        try { if (tunnel != null) { tunnel.close(); } } catch (Exception ignored) {}
        tunnel = null;
        output = null;
        configuring = false;
    }

    @Override public void onRevoke() {
        work.execute(() -> { closeTunnel(); message("Android revoked VPN permission; approve Mosaic again in VPN settings."); stopSelf(); });
    }

    @Override public void onDestroy() {
        connectivity.unregisterNetworkCallback(changes);
        work.execute(() -> closeTunnel());
        work.shutdown();
        reader.shutdownNow();
        super.onDestroy();
    }
}

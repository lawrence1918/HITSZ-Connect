package com.hitsz.connect;

import android.app.*;
import android.content.Intent;
import android.net.VpnService;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import mobile.Mobile;
import java.util.concurrent.atomic.AtomicBoolean;

public final class HITSZVpnService extends VpnService {
    public static final String ACTION_CONNECT = "com.hitsz.connect.CONNECT";
    public static final String ACTION_DISCONNECT = "com.hitsz.connect.DISCONNECT";
    private static volatile String serviceError = "";
    private ParcelFileDescriptor vpnInterface;
    private final AtomicBoolean connectStarted = new AtomicBoolean(false);

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            disconnectInternal();
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        createChannel(); startForeground(7, notification("正在连接 HITSZ aTrust"));
        if (intent != null && ACTION_CONNECT.equals(intent.getAction()) && beginConnect()) {
            new Thread(() -> connect(intent), "hitsz-connect").start();
        }
        return START_STICKY;
    }

    private boolean beginConnect() {
        if (connectStarted.get()) {
            String state = Mobile.hitszState();
            if (!"idle".equals(state) && !"error".equals(state)) return false;
            connectStarted.set(false);
        }
        return connectStarted.compareAndSet(false, true);
    }

    private void connect(Intent intent) {
        try {
            serviceError = "";
            Mobile.connectHitsz("trust.hitsz.edu.cn", 443, intent.getStringExtra("username"), intent.getStringExtra("password"), "", "hitcas", intent.getStringExtra("mfaMethod"), intent.getStringExtra("otpSecret"), intent.getStringExtra("clientData"));
            long deadline = System.currentTimeMillis() + 180000;
            while (System.currentTimeMillis() < deadline) {
                if (!connectStarted.get()) return;
                String state = Mobile.hitszState();
                if ("connected".equals(state)) break;
                if ("error".equals(state)) throw new IllegalStateException(Mobile.hitszLastError());
                Thread.sleep(250);
            }
            if (!connectStarted.get()) return;
            if (!"connected".equals(Mobile.hitszState())) throw new IllegalStateException("HITSZ 登录超时");
            String clientIp = Mobile.hitszClientIP();
            Builder builder = new Builder().setSession("HITSZ aTrust").setMtu(1400).addAddress(clientIp, 32).addDnsServer("10.248.98.30");
            int routeCount = 0;
            for (String route : Mobile.hitszRoutes().split(",")) {
                String[] parts = route.trim().split("/");
                if (parts.length == 2) {
                    builder.addRoute(parts[0], Integer.parseInt(parts[1]));
                    routeCount++;
                }
            }
            if (routeCount == 0) {
                builder.addRoute("10.248.0.0", 16).addRoute("10.249.0.0", 16).addRoute("10.250.0.0", 16);
            }
            builder.addDisallowedApplication(getPackageName());
            vpnInterface = builder.establish();
            if (vpnInterface == null) throw new IllegalStateException("系统 VPN 权限未授予");
            Mobile.startHitszTun(vpnInterface.getFd());
            new CredentialStore(this).put("clientData", Mobile.hitszClientData());
            updateNotification("HITSZ 已连接");
        } catch (Exception error) {
            serviceError = error.getMessage() == null ? "连接失败" : error.getMessage();
            updateNotification("连接失败: " + serviceError);
            disconnectInternal();
            stopSelf();
        }
    }

    static String lastError() { return serviceError; }

    private void disconnectInternal() {
        connectStarted.set(false);
        Mobile.logoutHitsz();
        if (vpnInterface != null) {
            try { vpnInterface.close(); } catch (Exception ignored) {}
            vpnInterface = null;
        }
    }

    @Override public void onDestroy() { disconnectInternal(); stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }
    private void createChannel() { if (android.os.Build.VERSION.SDK_INT >= 26) { NotificationChannel c = new NotificationChannel("hitsz", "HITSZ Connect", NotificationManager.IMPORTANCE_LOW); getSystemService(NotificationManager.class).createNotificationChannel(c); } }
    private Notification notification(String text) { return new Notification.Builder(this, "hitsz").setContentTitle("HITSZ Connect").setContentText(text).setSmallIcon(android.R.drawable.stat_sys_warning).setOngoing(true).build(); }
    private void updateNotification(String text) { getSystemService(NotificationManager.class).notify(7, notification(text)); }
}

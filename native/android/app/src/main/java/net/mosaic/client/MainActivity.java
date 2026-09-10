package net.mosaic.client;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public final class MainActivity extends Activity {
    private TextView status;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresh = new Runnable() {
        public void run() {
            status.setText(getSharedPreferences("mosaic", MODE_PRIVATE).getString("status", "Import a private configuration to connect."));
            handler.postDelayed(this, 1000);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        status = new TextView(this);
        status.setTextSize(18);
        layout.addView(status);
        button(layout, R.string.import_configuration, () -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(intent, 1);
        });
        button(layout, R.string.connect, () -> {
            Intent permission = VpnService.prepare(this);
            if (permission != null) { startActivityForResult(permission, 2); } else { connect(); }
        });
        button(layout, R.string.disconnect, () -> {
            startService(new Intent(this, TunnelService.class).setAction("disconnect"));
            startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
        });
        button(layout, R.string.vpn_settings, () -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
        TextView explanation = new TextView(this);
        explanation.setText(R.string.protection);
        layout.addView(explanation);
        setContentView(layout);
    }

    private void button(LinearLayout layout, int title, Runnable action) {
        Button button = new Button(this);
        button.setText(title);
        button.setOnClickListener(view -> action.run());
        layout.addView(button);
    }

    private void connect() { startForegroundService(new Intent(this, TunnelService.class).setAction("connect")); }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK) { message("Permission or file selection was cancelled"); return; }
        if (request == 2) { connect(); return; }
        if (request != 1 || data == null || data.getData() == null) { return; }
        if (getSharedPreferences("mosaic", MODE_PRIVATE).getBoolean("connected", false)) { message("Disconnect before replacing configuration"); return; }
        try (InputStream input = getContentResolver().openInputStream(data.getData()); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[4096];
            int count;
            while ((count = input.read(bytes)) != -1) {
                if (output.size() + count > 98304) { throw new Exception("Configuration exceeds size limit"); }
                output.write(bytes, 0, count);
            }
            ProfileStore.save(this, output.toByteArray());
            message("Private configuration imported");
        } catch (Exception error) { message("Cannot import this private configuration"); }
    }

    private void message(String text) { getSharedPreferences("mosaic", MODE_PRIVATE).edit().putString("status", text).apply(); }
    @Override protected void onResume() { super.onResume(); handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh); super.onPause(); }
}

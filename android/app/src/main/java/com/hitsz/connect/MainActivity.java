package com.hitsz.connect;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import mobile.Mobile;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST = 41;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private CredentialStore store;
    private EditText username, password, otpSecret, mfaCode;
    private Spinner mfaMethod;
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new CredentialStore(this);
        setContentView(buildView());
        pollState.run();
    }

    private View buildView() {
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(36, 24, 36, 24); root.setBackgroundColor(Color.rgb(16,19,24));
        TextView title = label("HITSZ Connect", 26); root.addView(title, weight(0));
        TextView hint = label("aTrust 校园资源 · Android TV / 机顶盒", 15); hint.setTextColor(Color.LTGRAY); root.addView(hint, weight(0));
        LinearLayout form = new LinearLayout(this); form.setOrientation(LinearLayout.VERTICAL);
        username = input("学号或手机号", false); username.setText(store.get("username")); form.addView(username);
        password = input("统一认证密码", true); password.setText(store.get("password")); form.addView(password);
        mfaMethod = new Spinner(this); String[] methods = {"App 动态码", "短信动态码", "OTP 安全令牌"}; mfaMethod.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, methods)); try { mfaMethod.setSelection(Integer.parseInt(store.get("mfaMethod"))); } catch (Exception ignored) {} form.addView(mfaMethod);
        otpSecret = input("OTP 种子或 otpauth URI（仅 OTP）", false); otpSecret.setText(store.get("otpSecret")); form.addView(otpSecret);
        mfaCode = input("App / 短信验证码", false); form.addView(mfaCode);
        root.addView(form, weight(1));
        status = label("未连接", 16); status.setTextColor(Color.LTGRAY); root.addView(status, weight(0));
        LinearLayout actions = new LinearLayout(this); actions.setGravity(Gravity.CENTER_VERTICAL);
        Button connect = button("连接"); connect.setOnClickListener(v -> requestVpn()); actions.addView(connect, buttonParams());
        Button submit = button("提交 MFA"); submit.setOnClickListener(v -> { try { Mobile.submitHitszMFACode(mfaCode.getText().toString()); mfaCode.setText(""); } catch (Exception e) { status.setText(e.getMessage()); } }); actions.addView(submit, buttonParams());
        Button disconnect = button("断开"); disconnect.setOnClickListener(v -> { Intent intent = new Intent(this, HITSZVpnService.class).setAction(HITSZVpnService.ACTION_DISCONNECT); startService(intent); }); actions.addView(disconnect, buttonParams());
        root.addView(actions, weight(0));
        return root;
    }

    private void requestVpn() {
        store.put("username", username.getText().toString()); store.put("password", password.getText().toString()); store.put("otpSecret", otpSecret.getText().toString()); store.put("mfaMethod", Integer.toString(mfaMethod.getSelectedItemPosition()));
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) startActivityForResult(prepare, VPN_REQUEST); else startVpnService();
    }
    @Override protected void onActivityResult(int request, int result, Intent data) { super.onActivityResult(request, result, data); if (request == VPN_REQUEST && result == RESULT_OK) startVpnService(); }
    private void startVpnService() {
        String[] methods = {"app", "sms", "otp"};
        Intent intent = new Intent(this, HITSZVpnService.class).setAction(HITSZVpnService.ACTION_CONNECT);
        intent.putExtra("username", username.getText().toString()); intent.putExtra("password", password.getText().toString()); intent.putExtra("mfaMethod", methods[mfaMethod.getSelectedItemPosition()]); intent.putExtra("otpSecret", otpSecret.getText().toString()); intent.putExtra("clientData", store.get("clientData"));
        startForegroundService(intent);
    }

    private final Runnable pollState = new Runnable() {
        public void run() {
            String state = Mobile.hitszState();
            String message;
            switch (state) {
                case "authenticating": message = "正在认证"; break;
                case "waiting_mfa": message = "等待 " + (mfaMethod.getSelectedItemPosition() == 0 ? "App" : "短信") + " 动态码"; break;
                case "connected": message = "已连接"; break;
                case "stopping": message = "正在断开"; break;
                case "error": message = Mobile.hitszLastError().isEmpty() ? "连接失败" : Mobile.hitszLastError(); break;
                default: message = HITSZVpnService.lastError().isEmpty() ? "未连接" : HITSZVpnService.lastError();
            }
            status.setText(message);
            handler.postDelayed(this, 500);
        }
    };
    @Override protected void onDestroy() { handler.removeCallbacks(pollState); super.onDestroy(); }
    private TextView label(String text, int size) { TextView v = new TextView(this); v.setText(text); v.setTextColor(Color.WHITE); v.setTextSize(size); v.setPadding(0, 8, 0, 8); return v; }
    private EditText input(String hint, boolean secret) { EditText v = new EditText(this); v.setHint(hint); v.setSingleLine(true); v.setTextColor(Color.WHITE); v.setHintTextColor(Color.GRAY); if (secret) v.setInputType(0x81); v.setFocusable(true); return v; }
    private Button button(String text) { Button b = new Button(this); b.setText(text); b.setMinHeight(56); b.setFocusable(true); return b; }
    private LinearLayout.LayoutParams weight(float weight) { return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, weight == 0 ? ViewGroup.LayoutParams.WRAP_CONTENT : 0, weight); }
    private LinearLayout.LayoutParams buttonParams() { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1); p.setMargins(8, 0, 8, 0); return p; }
}

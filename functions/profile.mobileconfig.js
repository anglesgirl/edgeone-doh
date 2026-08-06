// EdgeOne Pages Functions — iOS 描述文件（DoH 配置）
// 访问 /profile.mobileconfig 下载

export async function onRequest({ env }) {
  const dohDomain = env.DOH_DOMAIN || 'your-doh-domain.example.com';
  const uuid = () => {
    // 简化 UUID v4
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  };
  const uuid1 = uuid();
  const uuid2 = uuid();

  const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://${dohDomain}/dns-query</string>
			</dict>
			<key>PayloadDescription</key>
			<string>Encrypted DNS (DoH) via ${dohDomain}</string>
			<key>PayloadDisplayName</key>
			<string>ECH DoH</string>
			<key>PayloadIdentifier</key>
			<string>com.anglesgirl.doh.dns</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>${uuid1}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>系统 DNS 走 DoH：防污染 + 指定域名走自定义 IP + ECH</string>
	<key>PayloadDisplayName</key>
	<string>ECH DoH 配置</string>
	<key>PayloadIdentifier</key>
	<string>com.anglesgirl.doh.profile</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>${uuid2}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`;
  return new Response(profile, {
    headers: {
      'content-type': 'application/x-apple-aspen-config',
      'content-disposition': 'attachment; filename=ech-doh.mobileconfig',
    },
  });
}

import { useMemo } from "react";
import QRCode from "qrcode";

/** Encoded locally: the enrollment secret never goes to an image service. */
export function TotpQr({ uri }: { uri: string }): React.JSX.Element {
  const code = useMemo(() => QRCode.create(uri, { errorCorrectionLevel: "M" }), [uri]);
  const size = code.modules.size;
  const cells: string[] = [];
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (code.modules.data[y * size + x]) cells.push(`M${x + 4},${y + 4}h1v1h-1z`);
    }
  }
  return <svg role="img" aria-label="Scan this QR code with your authenticator app" viewBox={`0 0 ${size + 8} ${size + 8}`} width="224" height="224" className="totp-qr" shapeRendering="crispEdges">
    <rect width={size + 8} height={size + 8} fill="#fff" />
    <path d={cells.join("")} fill="#000" />
  </svg>;
}

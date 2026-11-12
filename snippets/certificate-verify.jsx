export const CertificateVerify = ({ registry }) => {
  const [certNo, setCertNo] = useState("");
  const [state, setState] = useState({ status: "idle" });

  const normalize = (value) => String(value || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

  const fromBase64 = (value) => Uint8Array.from(atob(value), (ch) => ch.charCodeAt(0));

  const toHex = (buffer) =>
    Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  const formatDate = (value) => {
    if (!value) return "";
    const date = new Date(`${value}T00:00:00`);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString("en-PH", { year: "numeric", month: "long", day: "numeric" });
  };

  const lookup = async (rawValue) => {
    const normalized = normalize(rawValue);
    if (normalized.length < 6) {
      setState({ status: "error", message: "Enter the full certificate number shown on your certificate." });
      return;
    }
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      setState({ status: "error", message: "Your browser can't run the verification check. Try a current version of Chrome, Edge, Firefox, or Safari." });
      return;
    }
    setState({ status: "checking" });
    try {
      const subtle = globalThis.crypto.subtle;
      const encoder = new TextEncoder();
      const baseKey = await subtle.importKey("raw", encoder.encode(normalized), "PBKDF2", false, ["deriveBits"]);
      const master = await subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: fromBase64(registry.kdf.salt), iterations: registry.kdf.iterations },
        baseKey,
        256
      );
      const hkdfKey = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
      const lookupBits = await subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode("cert-lookup") },
        hkdfKey,
        128
      );
      const lookupId = toHex(lookupBits);
      const record = registry.records[lookupId];
      if (!record) {
        setState({ status: "notfound", certNo: rawValue.trim() });
        return;
      }
      const aesKey = await subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode("cert-record") },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const plain = await subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(record.iv), additionalData: encoder.encode(lookupId) },
        aesKey,
        fromBase64(record.data)
      );
      const details = JSON.parse(new TextDecoder().decode(plain));
      setState({ status: details.status === "revoked" ? "revoked" : "valid", details });
    } catch (err) {
      setState({ status: "error", message: "Something went wrong while checking this certificate. Please try again." });
    }
  };

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const fromUrl = params.get("id") || params.get("cert");
    if (fromUrl) {
      setCertNo(fromUrl);
      lookup(fromUrl);
    }
  }, []);

  const onSubmit = (event) => {
    event.preventDefault();
    lookup(certNo);
  };

  const details = state.details;
  const row = (label, value) =>
    value ? (
      <div className="flex flex-col gap-0.5 sm:flex-row sm:gap-4">
        <dt className="w-40 shrink-0 text-sm text-gray-500 dark:text-gray-400">{label}</dt>
        <dd className="text-sm font-medium text-gray-900 dark:text-gray-100">{value}</dd>
      </div>
    ) : null;

  return (
    <div className="not-prose flex flex-col gap-5">
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="cert-no" className="sr-only">Certificate number</label>
        <input
          id="cert-no"
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder="e.g. U7K-7Q2M-XK4P-9DHT"
          value={certNo}
          onChange={(event) => setCertNo(event.target.value)}
          className="flex-1 rounded-lg border border-gray-300 bg-white px-4 py-2.5 font-mono text-base uppercase tracking-wide text-gray-900 outline-none focus:border-gray-500 dark:border-white/15 dark:bg-white/5 dark:text-gray-100"
        />
        <button
          type="submit"
          disabled={state.status === "checking"}
          className="rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-60 dark:bg-primary-light dark:text-gray-950"
        >
          {state.status === "checking" ? "Checking…" : "Verify"}
        </button>
      </form>

      {state.status === "valid" && (
        <div data-result="valid" className="rounded-xl border border-green-600/30 bg-green-50 p-5 dark:border-green-400/30 dark:bg-green-500/10">
          <p className="mb-4 text-base font-semibold text-green-800 dark:text-green-300">✓ Valid certificate</p>
          <dl className="flex flex-col gap-2">
            {row("Certificate no.", details.id)}
            {row("Awarded to", details.name)}
            {row("Training", details.course)}
            {row("Completed", formatDate(details.completed))}
            {row("Issued by", details.issuer || "Unit7000")}
          </dl>
        </div>
      )}

      {state.status === "revoked" && (
        <div data-result="revoked" className="rounded-xl border border-red-600/30 bg-red-50 p-5 dark:border-red-400/30 dark:bg-red-500/10">
          <p className="mb-4 text-base font-semibold text-red-800 dark:text-red-300">✕ This certificate has been revoked</p>
          <dl className="flex flex-col gap-2">
            {row("Certificate no.", details.id)}
            {row("Awarded to", details.name)}
            {row("Training", details.course)}
            {row("Revoked on", formatDate(details.revoked))}
          </dl>
        </div>
      )}

      {state.status === "notfound" && (
        <div data-result="notfound" className="rounded-xl border border-amber-600/30 bg-amber-50 p-5 dark:border-amber-400/30 dark:bg-amber-500/10">
          <p className="text-base font-semibold text-amber-800 dark:text-amber-300">No matching certificate</p>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
            We couldn't find a certificate with the number <span className="font-mono">{state.certNo}</span>. Check it against the certificate and try again.
          </p>
        </div>
      )}

      {state.status === "error" && (
        <div data-result="error" className="rounded-xl border border-gray-300 bg-gray-50 p-5 text-sm text-gray-700 dark:border-white/15 dark:bg-white/5 dark:text-gray-300">
          {state.message}
        </div>
      )}
    </div>
  );
};

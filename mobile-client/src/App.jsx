import {useEffect,useState} from 'react'
import {ShieldCheck,Smartphone,LockKeyhole,CheckCircle2,XCircle,KeyRound,AlertTriangle} from 'lucide-react'
import {motion} from 'framer-motion'
import {startRegistration,startAuthentication,browserSupportsWebAuthn} from '@simplewebauthn/browser'
import {API} from './services/socket'

const phoneId='GHANARAM-PHONE'
export default function App(){
 const [requestId,setRequestId]=useState(null),[registered,setRegistered]=useState(false),[supported,setSupported]=useState(true)
 const [message,setMessage]=useState('Ready'),[busy,setBusy]=useState(false),[online,setOnline]=useState(false)
useEffect(() => {
  const supportedNow = browserSupportsWebAuthn();

  setSupported(supportedNow);
  setOnline(navigator.onLine);

  const id = new URLSearchParams(window.location.search).get("request");

  console.log("📱 PHONE APP STARTED");
  console.log("Request ID:", id);
  console.log("WebAuthn supported:", supportedNow);
  console.log("API:", API);
  console.log("Phone ID:", phoneId);

  setRequestId(id);

  checkStatus();
}, []); const checkStatus=async()=>{try{const r=await fetch(`${API}/api/webauthn/status?deviceId=${phoneId}`);const d=await r.json();setRegistered(d.registered)}catch{setOnline(false)}}

const register = async () => {
  try {
    setBusy(true);
    setMessage("Creating secure passkey...");

    const url =
      `${API}/api/webauthn/register/options?deviceId=${phoneId}`;

    console.log("➡️ REGISTER OPTIONS URL:", url);

    const optionsResp = await fetch(url);

    console.log(
      "📡 Register options status:",
      optionsResp.status
    );

    console.log(
      "📡 Content-Type:",
      optionsResp.headers.get("content-type")
    );

    const raw = await optionsResp.text();

    console.log(
      "📦 Register options RAW:",
      raw
    );

    let options;

    try {
      options = JSON.parse(raw);
    } catch {
      throw new Error(
        "Register API returned non-JSON: " +
        raw.substring(0, 200)
      );
    }

    if (!optionsResp.ok) {
      throw new Error(
        options.error ||
        "Unable to create registration options"
      );
    }

    console.log("✅ REGISTER OPTIONS:", options);

    setMessage("Touch your phone's fingerprint/passkey...");

    console.log("REGISTER URL =", location.href);
console.log("RP ID FROM SERVER =", options.rp?.id || options.rpId);
console.log("OPTIONS =", options);
    const response = await startRegistration({
      optionsJSON: options,
    });

    console.log(
      "✅ PASSKEY CREATED:",
      response
    );

    const verifyResp = await fetch(
      `${API}/api/webauthn/register/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          deviceId: phoneId,
          response,
        }),
      }
    );

    const verifyRaw = await verifyResp.text();

    console.log(
      "📦 Register verify RAW:",
      verifyRaw
    );

    let verify;

    try {
      verify = JSON.parse(verifyRaw);
    } catch {
      throw new Error(
        "Register verify returned non-JSON"
      );
    }

    console.log("🔐 REGISTER VERIFY:", verify);

    if (!verifyResp.ok || !verify.verified) {
      throw new Error(
        verify.error ||
        "Registration verification failed"
      );
    }

    setRegistered(true);
    setMessage("✓ Real passkey registered on this phone");

  } catch (e) {

     console.log("========== REGISTRATION ERROR ==========");
  console.log("name:", e?.name);
  console.log("message:", e?.message);
  console.log("code:", e?.code);
  console.log("cause:", e?.cause);
  console.log("full:", e);
  console.log("========================================");

  setMessage(
    `❌ ${e?.name || "Error"}: ${e?.message || "Registration failed"}`
  );
    console.error(
      "❌ REGISTRATION ERROR:",
      e
    );

    setMessage(
      `❌ ${e?.name || "Error"}: ${
        e?.message || "Passkey registration failed"
      }`
    );

  } finally {
    setBusy(false);
  }
};

const authenticate = async () => {
  console.log("🔥 AUTH BUTTON CLICKED");
  console.log("requestId =", requestId);
  console.log("phoneId =", phoneId);
  console.log("registered =", registered);
  console.log("supported =", supported);

  if (!requestId) {
    console.error("❌ NO REQUEST ID");
    setMessage("No authentication request found");
    return;
  }

  try {
    setBusy(true);
    setMessage("Starting WebAuthn...");

    // ==========================================
    // STEP 1: GET AUTH OPTIONS
    // ==========================================

    console.log("➡️ STEP 1: Calling /auth/options");

    const optionsResp = await fetch(
      `${API}/api/webauthn/auth/options`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          requestId: requestId,
          deviceId: phoneId,
        }),
      }
    );

    console.log(
      "📡 Auth options HTTP status:",
      optionsResp.status
    );

    const optionsText = await optionsResp.text();

    console.log(
      "📦 Auth options raw response:",
      optionsText
    );

    let options;

    try {
      options = JSON.parse(optionsText);
    } catch (err) {
      throw new Error(
        "Server returned invalid JSON: " + optionsText
      );
    }

    console.log("✅ OPTIONS RECEIVED");
    console.log(options);

    if (!optionsResp.ok) {
      throw new Error(
        options.error ||
        "Unable to start authentication"
      );
    }

    // ==========================================
    // STEP 2: CHECK WEBAUTHN OPTIONS
    // ==========================================

    console.log("=================================");
    console.log("🔐 WEBAUTHN OPTIONS CHECK");
    console.log("challenge =", options.challenge);
    console.log(
      "rpId / expected RP ID = 192.168.0.141"
    );
    console.log(
      "allowCredentials =",
      options.allowCredentials
    );
    console.log(
      "userVerification =",
      options.userVerification
    );
    console.log("=================================");

    if (!options.challenge) {
      throw new Error(
        "WebAuthn challenge missing from server"
      );
    }

    if (
      !options.allowCredentials ||
      options.allowCredentials.length === 0
    ) {
      throw new Error(
        "No WebAuthn credential available"
      );
    }

    setMessage(
      "📱 Verify your identity using your phone..."
    );

    // ==========================================
    // STEP 3: START WEBAUTHN
    // ==========================================

    console.log(
      "➡️ STEP 3: Calling startAuthentication()..."
    );

    console.log(
      "⚠️ Browser should show fingerprint/passkey prompt now"
    );

    let response;

    try {
      response = await startAuthentication({
        optionsJSON: options,
      });

      console.log(
        "✅ STEP 3 SUCCESS - WebAuthn response received"
      );

      console.log(response);

    } catch (webauthnError) {

      console.error(
        "❌ STEP 3 WEBAUTHN ERROR"
      );

      console.error(
        "name:",
        webauthnError?.name
      );

      console.error(
        "message:",
        webauthnError?.message
      );

      console.error(
        "full error:",
        webauthnError
      );

      throw webauthnError;
    }

    // ==========================================
    // STEP 4: VERIFY ON SERVER
    // ==========================================

    setMessage(
      "🔐 Verifying secure authentication..."
    );

    console.log(
      "➡️ STEP 4: Calling /auth/verify"
    );

    const verifyResp = await fetch(
      `${API}/api/webauthn/auth/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          requestId: requestId,
          deviceId: phoneId,
          response: response,
        }),
      }
    );

    console.log(
      "📡 Verify HTTP status:",
      verifyResp.status
    );

    const verifyText = await verifyResp.text();

    console.log(
      "📦 Verify raw response:",
      verifyText
    );

    let verify;

    try {
      verify = JSON.parse(verifyText);
    } catch {
      throw new Error(
        "Invalid verification response"
      );
    }

    console.log(
      "🔐 Verification result:",
      verify
    );

    if (
      !verifyResp.ok ||
      !verify.verified
    ) {
      throw new Error(
        verify.error ||
        "Authentication verification failed"
      );
    }

    // ==========================================
    // SUCCESS
    // ==========================================

    console.log(
      "🎉 AUTHENTICATION SUCCESS!"
    );

    setMessage(
      "✓ Identity verified by WebAuthn"
    );

    setRequestId(null);

  } catch (e) {

    console.error(
      "================================="
    );

    console.error(
      "❌ AUTHENTICATION FAILED"
    );

    console.error(
      "Error name:",
      e?.name
    );

    console.error(
      "Error message:",
      e?.message
    );

    console.error(
      "Full error:",
      e
    );

    console.error(
      "================================="
    );

    setMessage(
      `❌ ${e?.name || "Error"}: ${
        e?.message || "Authentication failed"
      }`
    );

  } finally {
    setBusy(false);
  }
};

 async function deny() { if (!requestId) return; await fetch(`${API}/api/auth/deny`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ requestId, phoneDeviceId: phoneId }) }); setMessage('Access denied.'); setRequestId(null) }
 return <div className="min-h-screen px-4 py-6">
  <div className="mx-auto max-w-md">
   <header className="flex items-center justify-between"><div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl bg-cyan-300/10 text-cyan-300"><ShieldCheck/></div><div><b className="tracking-[.2em]">BIOLOCK</b><p className="text-[10px] text-slate-500">REAL WEBAUTHN AUTHORIZATION</p></div></div><span className={online?'text-emerald-300':'text-red-300'}>●</span></header>
   {!supported&&<div className="mt-5 rounded-2xl border border-amber-300/20 bg-amber-300/5 p-4 text-sm text-amber-100"><AlertTriangle className="mr-2 inline"/>This browser does not expose WebAuthn.</div>}
   <main className="mt-8 space-y-5">
    <div className="glass rounded-3xl p-6"><div className="flex items-center gap-3"><Smartphone className="text-cyan-300"/><div><p className="text-sm text-slate-400">Trusted Device</p><h1 className="text-xl font-bold">Ghanaram's Phone</h1></div></div><div className="mt-6 rounded-2xl bg-emerald-400/5 p-4"><p className="text-sm text-emerald-300">● {registered?'REAL PASSKEY REGISTERED':'NO PASSKEY REGISTERED'}</p><p className="mt-1 text-xs text-slate-500">Biometric verification is performed by the phone's platform authenticator.</p></div>{!registered&&<button disabled={busy||!supported} onClick={register} className="mt-4 w-full rounded-xl bg-cyan-400 px-4 py-3 font-bold text-slate-950"><KeyRound className="mr-2 inline" size={17}/>{busy?'REGISTERING...':'REGISTER THIS PHONE'}</button>}</div>
    {requestId?<motion.div initial={{opacity:0,y:15}} animate={{opacity:1,y:0}} className="glass rounded-3xl p-6"><div className="mb-6 flex items-center gap-3"><div className="rounded-xl bg-cyan-300/10 p-3 text-cyan-300"><LockKeyhole/></div><div><p className="text-xs text-cyan-300">ACCESS REQUEST</p><h1 className="text-2xl font-bold">BIOLOCK-PC-01</h1></div></div><div className="space-y-3"><Row label="Location" value="Secure Web Session"/><Row label="Request" value="PC Unlock"/><Row label="Device" value="BIOLOCK-PC-01"/></div><div className="mt-7 rounded-2xl border border-cyan-300/10 bg-cyan-300/5 p-5 text-center"><KeyRound className="mx-auto text-cyan-300" size={38}/><p className="mt-3 font-semibold">Verify your identity</p><p className="mt-2 text-xs leading-5 text-slate-500">WebAuthn asks your phone's platform authenticator to verify you. Depending on your device this can be fingerprint, Face ID, screen lock or a passkey. BioLock receives only the signed authentication result.</p></div>
    <button
    disabled={busy}
  //{busy || !registered || !supported}
  onClick={() => {
    console.log("BUTTON CLICK");
    authenticate();
  }}
  className="mt-5 w-full rounded-xl bg-cyan-400 py-4 font-bold text-slate-950"
>
  {busy ? "AUTHENTICATING..." : "AUTHENTICATE WITH PHONE"}
</button>{!registered&&<p className="mt-2 text-center text-xs text-amber-300">Register the phone passkey above first.</p>}<button onClick={deny} disabled={busy} className="mt-3 w-full rounded-xl border border-red-300/20 py-4 text-red-200"><XCircle className="mr-2 inline" size={17}/>DENY</button></motion.div>:<div className="glass rounded-3xl p-6"><CheckCircle2 className="text-emerald-300" size={34}/><h2 className="mt-3 text-2xl font-bold">{message}</h2><p className="mt-3 text-sm text-slate-500">To authorize a PC, scan the QR generated by BioLock-PC-01.</p></div>}
    <div className="text-center text-xs text-slate-600">Private key and biometric data stay inside the authenticator.</div>
   </main>
  </div>
 </div>
}


function Row({label,value}){return <div className="flex justify-between rounded-xl bg-white/[.03] p-4"><span className="text-slate-500">{label}</span><b>{value}</b></div>}

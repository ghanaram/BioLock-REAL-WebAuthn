import {useEffect,useMemo,useState} from 'react'
import {ShieldCheck,LockKeyhole,Smartphone,Activity,Settings,AlertTriangle,CheckCircle2,XCircle,RefreshCw,Clock3,LogOut} from 'lucide-react'
import {motion,AnimatePresence} from 'framer-motion'
import React from "react";
import {API,socket} from './services/socket'
const AGENT_STATUS_URL = 'http://127.0.0.1:47821/status'

const pcId='BIOLOCK-PC-01'
const fmt=t=>new Date(t).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})

function AdminLogin({ onLogin }) {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API}/api/admin/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.ok) {
        throw new Error(data.error || "Invalid admin credentials");
      }

      onLogin();

    } catch (error) {
      console.error("❌ Admin login failed:", error);
      setError(error.message);

    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white grid place-items-center px-4">

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl"
      >

        <div className="text-center mb-8">

          <div className="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-2xl bg-cyan-400/10">
            <ShieldCheck className="text-cyan-300" size={34} />
          </div>

          <h1 className="text-2xl font-bold">
            BioLock Admin
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Authenticate to access the security dashboard
          </p>

        </div>

        <form onSubmit={handleLogin} className="space-y-5">

          <div>
            <label className="mb-2 block text-sm text-slate-300">
              Username
            </label>

            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 outline-none focus:border-cyan-400"
              placeholder="Admin username"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="mb-2 block text-sm text-slate-300">
              Password
            </label>

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 outline-none focus:border-cyan-400"
              placeholder="Admin password"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-cyan-400 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-50"
          >
            {loading ? "Authenticating..." : "Login to BioLock"}
          </button>

        </form>

      </motion.div>

    </div>
  );
}

export default function App(){
 const [agentStatus,setAgentStatus]=useState(null)
 const [adminAuthenticated, setAdminAuthenticated] = useState(false);
const [checkingAdmin, setCheckingAdmin] = useState(true);
const [page,setPage]=useState('lock'),[locked,setLocked]=useState(true),[request,setRequest]=useState(null)
 const [status,setStatus]=useState('Waiting for authorization...'),[events,setEvents]=useState([]),[devices,setDevices]=useState([])
 const [session,setSession]=useState(null),[connected,setConnected]=useState(false)
 const [seconds,setSeconds]=useState(0)
 const [pcStatus, setPcStatus] = useState({
  pcId: pcId,
  hostname: "-",
  platform: "-",
  agentRunning: false,
  socketConnected: false,
  registered: false,
  pcAuthorized: false,
  authorizedDevice: null,
  authorizationTime: null
});

const [lastSeen, setLastSeen] = useState(null);

const loadPcStatus = async () => {
  try {
    const response = await fetch("http://127.0.0.1:47821/status", {
      cache: "no-store"
    });

    if (!response.ok) {
      throw new Error("Agent unavailable");
    }

    const data = await response.json();

    setPcStatus(data);
    setLastSeen(new Date());
  } catch (error) {
    setPcStatus(prev => ({
      ...prev,
      agentRunning: false,
      socketConnected: false,
      registered: false,
      pcAuthorized: false
    }));
  }
};
const load = async () => {
  try {
    const eventsResponse = await fetch(`${API}/api/security-events`, {
      credentials: "include",
    });

    const eventsData = await eventsResponse.json();

    if (eventsResponse.status === 401) {
      setAdminAuthenticated(false);
      return;
    }

    setEvents(eventsData.events || []);

    const devicesResponse = await fetch(`${API}/api/devices`, {
      credentials: "include",
    });

    if (devicesResponse.status === 401) {
      setAdminAuthenticated(false);
      return;
    }

    const devicesData = await devicesResponse.json();
console.log("📡 DEVICES API AFTER AUTH:", devicesData);
setDevices(devicesData);

  } catch (error) {
    console.error("❌ Admin protected API error:", error);
  }
};

const checkAdminSession = async () => {
  try {
    const response = await fetch(`${API}/api/admin/session`, {
      credentials: "include",
      cache: "no-store",
    });

    const data = await response.json();

    const authenticated = data.authenticated === true;

    setAdminAuthenticated(authenticated);

    if (authenticated) {
      await load();
    }

  } catch (error) {
    console.error("❌ Admin session check failed:", error);
    setAdminAuthenticated(false);

  } finally {
    setCheckingAdmin(false);
  }
};
 const newRequest=async()=>{try{const r=await fetch(`${API}/api/auth/request`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pcDeviceId:pcId})});const d=await r.json();setRequest(d);setStatus('Waiting for phone authorization...');window.history.replaceState({},'',`?request=${d.requestId}`);setLocked(true);setSeconds(60)}catch{setStatus('Server unavailable')}}
//  useEffect(()=>{load();socket.on('connect',()=>setConnected(true));socket.on('disconnect',()=>setConnected(false))
//  socket.on('pc:access-granted',d=>{setLocked(false);setStatus('BIOLOCK UNLOCKED');setSession({device:d.deviceId,time:new Date()});setPage('lock');load()})
//  socket.on('pc:access-denied',()=>{setLocked(true);setStatus('ACCESS DENIED');load()})
//  socket.on('demo:reset',()=>{setLocked(true);setRequest(null);setSession(null);setStatus('Waiting for authorization...');setPage('lock')})
//  socket.on('security:event',()=>load())
//  return()=>socket.removeAllListeners()},[])
useEffect(() => {
  checkAdminSession();

  const checkAgentStatus = async () => {
    try {
      const r = await fetch(AGENT_STATUS_URL);
      const d = await r.json();
      console.log("🤖 PC AGENT STATUS:", d);
      setAgentStatus((prev) => ({
        ...d,
        expiresAt: d.expiresAt ?? prev?.expiresAt ?? null,
      }));
      setDevices((prev) =>
  prev.map((pc) =>
    pc.device_id === d.pcId ||
    pc.device_id === "BIOLOCK-PC-01"
      ? {
          ...pc,
          status:
            d.agentRunning && d.socketConnected
              ? "active"
              : "offline",
          pc_authorized: d.pcAuthorized ? 1 : 0,
          pc_authorized_device: d.authorizedDevice ?? null,
          pc_authorized_at: d.authorizationTime ?? null,
          pc_last_seen: new Date().toISOString(),
        }
      : pc
  )
);
      if (d.pcAuthorized) {
        setLocked(false);
        setStatus("BIOLOCK UNLOCKED");

        setSession({
          device: d.authorizedDevice,
          time: d.authorizationTime,
        });
      } else {
        setLocked(true);
      }

    } catch (e) {
      console.log("⚠️ PC Agent unavailable");
      setAgentStatus((prev) => prev);
    }
  };

  checkAgentStatus();

  const agentTimer = setInterval(checkAgentStatus, 2000);

  socket.on("connect", () => {
    console.log("🟢 PC CLIENT SOCKET CONNECTED:", socket.id);
    setConnected(true);
  });

  socket.on("disconnect", (reason) => {
    console.log("🔴 PC CLIENT SOCKET DISCONNECTED:", reason);
    setConnected(false);
  });

  socket.on("pc:access-granted", (d) => {
    console.log("🔥 PC CLIENT ACCESS GRANTED:", d);

    setLocked(false);
    setStatus("BIOLOCK UNLOCKED");

    setSession({
      device: d.deviceId,
      time: new Date(),
    });

    setPage("lock");

    load();
  });

  socket.on("pc:status-updated", (data) => {
    console.log("🔄 PC STATUS UPDATED:", data);

  setDevices((prev) =>
  prev.map((pc) =>
    pc.device_id === data.pcDeviceId
      ? {
          ...pc,
          pc_authorized: data.authorized ? 1 : 0,
          pc_authorized_device: data.authorizedDevice ?? null,
          pc_authorized_at: data.authorizedAt ?? null,
          pc_last_seen: data.lastSeen ?? pc.pc_last_seen,
          status:
            data.status === "CONNECTED" ||
            data.status === "connected"
              ? "active"
              : data.status ?? pc.status,
        }
      : pc
  )
);

    setAgentStatus((prev) => {
      const authorized = data.authorized === true;

      return {
        ...prev,
        pcAuthorized: authorized,
        authorizedDevice: authorized
          ? (data.authorizedDevice ?? prev.authorizedDevice)
          : null,
        authorizationTime: authorized
          ? (data.authorizedAt ?? prev.authorizationTime)
          : null,
        expiresAt: authorized
          ? (data.expiresAt ?? prev.expiresAt)
          : null,
      };
    });
  });

  socket.on("security:event-created", (event) => {
    console.log("🔴 LIVE SECURITY EVENT:", event);

    setEvents((prev) => {
      if (prev.some((e) => e.id === event.id)) {
        return prev;
      }

      return [event, ...prev].slice(0, 100);
    });
  });

  socket.on("pc:access-revoked", (d) => {
    console.log("🔒 PC CLIENT ACCESS REVOKED:", d);

    setLocked(true);
    setSession(null);
    setRequest(null);
    setStatus("PC LOCKED");

    load();
    loadPcStatus();
  });

  return () => {
    clearInterval(agentTimer);

    socket.off("connect");
    socket.off("disconnect");
    socket.off("pc:access-granted");
    socket.off("pc:status-updated");
    socket.off("security:event-created");
    socket.off("pc:access-revoked");
  };

}, []);
 useEffect(()=>{if(!request||seconds<=0)return;const x=setInterval(()=>setSeconds(s=>s-1),1000);return()=>clearInterval(x)},[request,seconds])
 useEffect(()=>{if(seconds===0&&request)setStatus('QR CODE EXPIRED')},[seconds])
  if (checkingAdmin) {
  return (
    <div className="min-h-screen bg-slate-950 text-white grid place-items-center">
      <div className="text-center">
        <ShieldCheck
          className="mx-auto animate-pulse text-cyan-300"
          size={48}
        />

        <p className="mt-4 text-sm text-slate-400">
          Verifying admin session...
        </p>
      </div>
    </div>
  );
}

if (!adminAuthenticated) {
  return (
    <AdminLogin
      onLogin={async () => {
        setAdminAuthenticated(true);
        await load();
      }}
    />
  );
}
 const simulate=async()=>{socket.emit('security:event',{type:'UNAUTHORIZED',severity:'CRITICAL',deviceId:pcId,message:'Multiple unauthorized access attempts detected.'});setStatus('UNAUTHORIZED ACCESS ATTEMPT');await load()}
 const reset=async()=>{await fetch(`${API}/api/demo/reset`,{method:'POST'})}
 return <div className="min-h-screen">
  <header className="sticky top-0 z-20 border-b border-cyan-300/10 bg-[#050816]/80 backdrop-blur-xl">
   <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
    <button onClick={()=>setPage('lock')} className="flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400/10 text-cyan-300"><ShieldCheck/></div><div className="text-left"><b className="tracking-[.25em]">BIOLOCK</b><p className="text-[10px] text-slate-400">SMARTPHONE AUTHORIZATION</p></div></button>
    <div className="flex items-center gap-3 text-xs"><span className={connected?'text-emerald-300':'text-red-300'}>● {connected?'Online':'Offline'}</span><button onClick={()=>setPage('dashboard')} className="rounded-lg px-3 py-2 hover:bg-white/5">Dashboard</button><button onClick={()=>setPage('devices')} className="rounded-lg px-3 py-2 hover:bg-white/5">Devices</button>
    <button
  onClick={async () => {
    try {
      await fetch(`${API}/api/admin/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (error) {
      console.error("❌ Admin logout failed:", error);
    }

    setAdminAuthenticated(false);
    setPage("lock");
    setEvents([]);
    setDevices([]);
  }}
  className="rounded-lg px-3 py-2 text-red-300 hover:bg-red-400/10"
>
  <LogOut className="mr-1 inline" size={14} />
  Logout
</button>
    </div>
   </div>
  </header>
  <main className="mx-auto max-w-7xl px-5 py-8">
   {page==='lock'&&<Lock locked={locked} request={request} status={status} seconds={seconds} onNew={newRequest} session={session} agentStatus={agentStatus} 
   onLogout={async () => {
  try {
    await fetch(`${API}/api/auth/lock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        pcDeviceId: pcId
      })
    });

    setLocked(true);
    setSession(null);
    setRequest(null);
    setStatus("PC LOCKED");
  } catch (e) {
    console.error("Lock failed:", e);
  }
}}/>}
   {page==='dashboard'&&<Dashboard events={events} devices={devices} onSimulate={simulate} onReset={reset} agentStatus={agentStatus}/>}
   {page==='devices'&&<Devices devices={devices} load={load}/>}
  </main>
 </div>
}
function Lock({locked,request,status,seconds,onNew,session,agentStatus,onLogout}){
 return <section className="mx-auto max-w-5xl">
  <div className="mb-6 flex items-center justify-between"><div><p className="text-sm text-cyan-300">PROTECTED ENVIRONMENT</p><h1 className="mt-1 text-3xl font-bold md:text-5xl">Your Phone. Your Fingerprint. Your PC.</h1></div><span className={`rounded-full px-3 py-1 text-xs ${locked?'bg-red-400/10 text-red-300':'bg-emerald-400/10 text-emerald-300'}`}>{locked?'🔒 PC PROTECTED':'🟢 UNLOCKED'}</span></div>
  <div className="glass glow rounded-3xl p-6 md:p-10">
   <AnimatePresence mode="wait">{locked?<motion.div key="locked" initial={{opacity:0,y:12}} animate={{opacity:1,y:0}} className="grid gap-8 md:grid-cols-[1.2fr_.8fr]">
    <div><div className="mb-6 flex h-28 w-28 items-center justify-center rounded-full border border-cyan-300/20 bg-cyan-300/5 text-cyan-300"><LockKeyhole size={52}/></div><p className="text-sm text-slate-400">Authentication</p><h2 className="text-2xl font-semibold">{status}</h2><div className="mt-7 grid grid-cols-2 gap-3">
        <div className="mt-4 rounded-xl border border-cyan-300/10 bg-cyan-300/5 p-4">
  <div className="flex items-center justify-between">
    <div>
      <p className="text-[10px] uppercase tracking-wider text-slate-500">
        PC Agent
      </p>

      <p className="mt-1 text-sm font-medium">
        {agentStatus?.agentRunning
          ? agentStatus.pcAuthorized
            ? "🟢 AUTHORIZED"
            : "🔒 LOCKED"
          : "⚠️ AGENT OFFLINE"}
      </p>
    </div>

    <div
      className={`h-3 w-3 rounded-full ${
        agentStatus?.pcAuthorized
          ? "bg-emerald-400"
          : agentStatus?.agentRunning
          ? "bg-amber-400"
          : "bg-red-400"
      }`}
    />
  </div>

  {agentStatus?.pcAuthorized && (
    <div className="mt-3 text-xs text-slate-400">
      <p>
        Authorized Device:{" "}
        <span className="text-slate-200">
          {agentStatus.authorizedDevice}
        </span>
      </p>

      <p className="mt-1">
        Authorization Time:{" "}
        <span className="text-slate-200">
          {agentStatus.authorizationTime
            ? fmt(agentStatus.authorizationTime)
            : "--"}
        </span>
      </p>
    </div>
  )}
</div>
        <Info label="Device" value="BIOLOCK-PC-01"/><Info label="Registered Phone" value={agentStatus?.authorizedDevice || "No active device"}/><Info label="Connection" value={agentStatus?.socketConnected && agentStatus?.registered? "Online" : "Ofline"}/><Info label="PC Authorization" value={agentStatus?.pcAuthorized? "AUTHORIZED" : "LOCKED"}/><Info label="Method" value="Smartphone"/></div></div>
    <div className="rounded-2xl border border-cyan-300/10 bg-black/20 p-5 text-center"><div className="mb-4 flex items-center justify-center gap-2 text-sm text-slate-300"><Smartphone size={16}/> Scan with your trusted smartphone</div>{request&&seconds>0?<img src={request.qrDataUrl} className="mx-auto w-64 rounded-xl bg-white p-3" alt="BioLock authorization QR"/>:<div className="mx-auto grid aspect-square w-64 place-items-center rounded-xl border border-dashed border-cyan-300/20 text-slate-500">QR READY</div>}<p className="mt-4 text-sm">{request&&seconds>0?`Expires in 00:${String(seconds).padStart(2,'0')}`:'Generate an authorization request'}</p><button onClick={onNew} className="mt-4 w-full rounded-xl bg-cyan-400 px-4 py-3 font-semibold text-slate-950 hover:bg-cyan-300"><RefreshCw className="mr-2 inline" size={16}/>Generate New QR</button><p className="mt-3 text-[11px] text-slate-500">Scan with your phone. The phone opens the real WebAuthn passkey authorization page.</p>
<p className="mt-2 text-[10px] text-cyan-300/70">No fingerprint data is transmitted to BioLock.</p></div>
   </motion.div>:<motion.div key="open" initial={{opacity:0,scale:.96}} animate={{opacity:1,scale:1}} className="py-10 text-center"><CheckCircle2 className="mx-auto text-emerald-300" size={80}/><p className="mt-5 text-sm text-emerald-300">SECURE CHANNEL ESTABLISHED</p><h2 className="mt-2 text-4xl font-bold">BIOLOCK UNLOCKED</h2><p className="mx-auto mt-3 max-w-xl text-slate-400">The protected demo environment is active. No biometric data was received by this application.</p><div className="mx-auto mt-8 max-w-md rounded-2xl bg-white/5 p-5 text-left"><Info label="Authenticated Device" value={session?.device||"Trusted Phone"}/><Info label="Authentication Time" value={session?.time?fmt(session.time):"Now"}/><Info label="State" value="Active session"/></div><button onClick={onLogout} className="mt-6 rounded-xl border border-white/10 px-5 py-3 hover:bg-white/5"><LogOut className="mr-2 inline" size={16}/>Lock Now</button></motion.div>}</AnimatePresence>
  </div>
 </section>
}
function Info({label,value}){return <div className="rounded-xl bg-white/[.03] p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 text-sm font-medium text-slate-200">{value}</p></div>}
function getRemainingSession(expiresAt) {
  if (!expiresAt) return null;

  const remaining = Math.max(
    0,
    new Date(expiresAt).getTime() - Date.now()
  );

  const totalSeconds = Math.floor(remaining / 1000);

  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  return {
    expired: remaining <= 0,
    text: `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`,
  };
}
function Dashboard({events,devices,onSimulate,onReset,agentStatus}){ const [remainingSession, setRemainingSession] = React.useState(null);  const isAuthorized = agentStatus?.pcAuthorized === true;
React.useEffect(() => {

  const updateCountdown = () => {

    console.log("⏱️ COUNTDOWN STATE:", {
      authorized: agentStatus?.pcAuthorized,
      expiresAt: agentStatus?.expiresAt,
    });

    if (
      !agentStatus?.pcAuthorized ||
      !agentStatus?.expiresAt
    ) {
      setRemainingSession(null);
      return;
    }

    const result = getRemainingSession(
      agentStatus.expiresAt
    );

    console.log("⏳ REMAINING:", result);

    setRemainingSession(result);
  };

  updateCountdown();

  const timer = setInterval(
    updateCountdown,
    1000
  );

  return () => clearInterval(timer);

}, [
  agentStatus?.pcAuthorized,
  agentStatus?.expiresAt
]);
return <div><div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm text-cyan-300">SECURITY CENTER</p><h1 className="text-4xl font-bold">BioLock Dashboard</h1></div><div className="flex gap-2"><button onClick={onSimulate} className="rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200"><AlertTriangle className="mr-2 inline" size={16}/>Simulate Unauthorized Attempt</button>
<button
  onClick={async () => {
    const pcId =
      agentStatus?.pcId || "BIOLOCK-PC-01";

    const confirmed =
      window.confirm(
        `Lock ${pcId} now?`
      );

    if (!confirmed) return;

    try {
      const response = await fetch(
        `${API}/api/pcs/${encodeURIComponent(pcId)}/lock`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      if (!response.ok || !data.ok) {
        throw new Error(
          data.error || "Failed to lock PC"
        );
      }

      console.log(
        "🔒 PC LOCKED:",
        data
      );

    } catch (error) {
      console.error(
        "❌ LOCK NOW failed:",
        error
      );

      alert(
        `Failed to lock PC: ${error.message}`
      );
    }
  }}
  disabled={!agentStatus?.socketConnected}
  className="rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-200 hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-40"
>
  <LockKeyhole
    className="mr-2 inline"
    size={16}
  />
  LOCK NOW
</button>

<button onClick={onReset} className="rounded-xl border border-white/10 px-4 py-3 text-sm"><RefreshCw className="mr-2 inline" size={16}/>Reset Demo</button></div></div>
<div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4"><Stat icon={<LockKeyhole/>} label="PC STATUS" value={!agentStatus?.agentRunning ? "Offline" : agentStatus?.pcAuthorized ? "Authorized" : "locked"}/><Stat icon={<Smartphone/>} label="PHONE STATUS" value="Trusted"/><Stat icon={<CheckCircle2/>} label="AUTHENTICATIONS" value={events.filter(x=>x.event_type==='SUCCESS').length}/><Stat icon={<XCircle/>} label="SECURITY EVENTS" value={events.length}/></div>

<div className="mt-6 glass rounded-2xl p-6">
  <div className="flex items-center justify-between">
    <div>
      <p className="text-sm text-cyan-300">LIVE AGENT MONITOR</p>
      <h2 className="mt-1 text-xl font-semibold">
        {agentStatus?.hostname || "Unknown PC"}
      </h2>
    </div>

    <span
      className={`rounded-full px-3 py-1 text-xs ${
        agentStatus?.socketConnected && agentStatus?.registered
          ? "bg-emerald-400/10 text-emerald-300"
          : "bg-red-400/10 text-red-300"
      }`}
    >
      ●{" "}
      {agentStatus?.socketConnected && agentStatus?.registered
        ? "ONLINE"
        : "OFFLINE"}
    </span>
  </div>

  <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
    <Info
      label="PC ID"
      value={agentStatus?.pcId || "BIOLOCK-PC-01"}
    />

    <Info
      label="Platform"
      value={agentStatus?.platform || "Windows"}
    />

    <Info
      label="Authorization"
      value={
        agentStatus?.pcAuthorized
          ? "AUTHORIZED"
          : "LOCKED"
      }
    />

    <Info
      label="Authorized Device"
      value={
        agentStatus?.authorizedDevice || "None"
      }
    />
    <Info
  label="SESSION"
  value={
    agentStatus?.pcAuthorized
      ? remainingSession?.text || "CALCULATING..."
      : "LOCKED"
  }
/>
  </div>
</div>
<div className="mt-6 grid gap-6 lg:grid-cols-[1.3fr_.7fr]"><div className="glass rounded-2xl p-6"><h2 className="text-xl font-semibold">Recent Security Activity</h2><span className="flex items-center gap-2 rounded-full bg-emerald-400/10 px-3 py-1 text-[10px] text-emerald-300">
    <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-300" />
    LIVE
  </span><div className="mt-5 space-y-3">
{events.slice(0, 8).map((e, i) => (
  <motion.div
    key={e.id || i}
    initial={{ opacity: 0, x: -10 }}
    animate={{ opacity: 1, x: 0 }}
    className="flex items-start gap-3 rounded-xl bg-white/[.03] p-4"
  >
    <div className="mt-1">
      {e.severity === "CRITICAL" ? (
        <AlertTriangle className="text-red-300" />
      ) : e.event_type === "DENIED" ? (
        <XCircle className="text-amber-300" />
      ) : e.event_type === "SUCCESS" ? (
        <CheckCircle2 className="text-emerald-300" />
      ) : (
        <Activity className="text-cyan-300" />
      )}
    </div>

    <div className="flex-1">
      <div className="flex justify-between gap-3">
        <b>{e.event_type}</b>

        <span className="text-xs text-slate-500">
          {fmt(e.created_at)}
        </span>
      </div>

      <p className="mt-1 text-sm text-slate-400">
        {e.message}
      </p>

      {e.device_id && (
        <p className="mt-2 text-[10px] text-cyan-300/70">
          DEVICE: {e.device_id}
        </p>
      )}
    </div>
  </motion.div>
))}
    </div></div>
<div className="glass rounded-2xl p-6"><h2 className="text-xl font-semibold">AI Security Insight</h2><div className="mt-5 rounded-xl border border-cyan-300/10 bg-cyan-300/5 p-4"><p className="text-sm text-cyan-100">Prototype Security Insight</p><p className="mt-2 text-sm text-slate-400">{events.filter(e=>['DENIED','RECOVERY_FAILED','UNAUTHORIZED'].includes(e.event_type)).length>=3?'Multiple denied/failed events were detected. This pattern may indicate an unauthorized access attempt.':'No suspicious pattern detected in the current demo logs.'}</p></div><h2 className="mt-8 text-xl font-semibold">Trusted Devices</h2><div className="mt-3 space-y-2">{devices.map(d=><div key={d.device_id} className="rounded-xl bg-white/[.03] p-3"><p className="font-medium">{d.device_name}</p><p className="text-xs text-emerald-300">● {d.trust_status||'Active'}</p></div>)}</div></div></div></div>}
function Stat({icon,label,value}){return <div className="glass rounded-2xl p-5"><div className="text-cyan-300">{icon}</div><p className="mt-4 text-[11px] tracking-wider text-slate-500">{label}</p><p className="mt-1 text-2xl font-bold">{value}</p></div>}
function Devices({ devices, load }) {
  const [busyDevice, setBusyDevice] = React.useState(null);
  const [message, setMessage] = React.useState(null);

  const handleAction = async (device, action) => {
    const deviceId = device.device_id;

    const actionText =
      action === "revoke"
        ? "revoke"
        : "re-trust";

    const confirmed = window.confirm(
      `${actionText.toUpperCase()} device "${device.device_name}"?`
    );

    if (!confirmed) return;

    try {
      setBusyDevice(deviceId);
      setMessage(null);

      const response = await fetch(
        `${API}/api/devices/${encodeURIComponent(deviceId)}/${action}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
        }
      );

      const data = await response.json();

      if (!response.ok || !data.ok) {
        throw new Error(
          data.error || `Failed to ${actionText} device`
        );
      }

      setMessage({
        type: "success",
        text:
          action === "revoke"
            ? `${deviceId} has been revoked.`
            : `${deviceId} has been re-trusted.`,
      });

      await load();
    } catch (error) {
      console.error(
        `❌ Device ${action} failed:`,
        error
      );

      setMessage({
        type: "error",
        text: error.message,
      });
    } finally {
      setBusyDevice(null);
    }
  };

  return (
    <div>
      <p className="text-sm text-cyan-300">
        TRUST MANAGEMENT
      </p>

      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-4xl font-bold">
            Trusted Devices
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Manage smartphones and PCs connected to BioLock.
          </p>
        </div>

        <button
          onClick={load}
          className="rounded-xl border border-white/10 px-4 py-2 text-sm hover:bg-white/5"
        >
          <RefreshCw
            className="mr-2 inline"
            size={15}
          />
          Refresh
        </button>
      </div>

      {message && (
        <div
          className={`mt-5 rounded-xl border p-4 text-sm ${
            message.type === "success"
              ? "border-emerald-300/20 bg-emerald-400/10 text-emerald-300"
              : "border-red-300/20 bg-red-400/10 text-red-300"
          }`}
        >
          {message.type === "success" ? "✓ " : "⚠ "}
          {message.text}
        </div>
      )}

      <div className="mt-8 grid gap-4 md:grid-cols-2">
        {devices.map((d) => {
          const isPhone = d.device_type === "phone";

          // Only phones have trust/revoke state.
          // PCs are managed separately by their connection/authorization state.
          const isTrusted =
            isPhone && d.trust_status === "trusted";

          const isRevoked =
            isPhone && d.trust_status === "revoked";

          const isBusy =
            busyDevice === d.device_id;

          return (
            <motion.div
              key={d.device_id}
              initial={{
                opacity: 0,
                y: 10,
              }}
              animate={{
                opacity: 1,
                y: 0,
              }}
              className="glass rounded-2xl p-6"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex gap-4">
                  <div className="rounded-xl bg-cyan-300/10 p-3 text-cyan-300">
                    {isPhone ? (
                      <Smartphone />
                    ) : (
                      <ShieldCheck />
                    )}
                  </div>

                  <div>
                    <h2 className="font-semibold">
                      {d.device_name}
                    </h2>

                    <p className="mt-1 text-xs text-slate-500">
                      {d.device_id}
                    </p>

                   <div className="mt-3 flex items-center gap-2">
  <span
    className={`h-2 w-2 rounded-full ${
      isPhone
        ? isTrusted
          ? "bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.7)]"
          : "bg-red-400 shadow-[0_0_10px_rgba(248,113,113,0.7)]"
        : d.status === "active"
          ? "bg-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.7)]"
          : "bg-slate-400 shadow-[0_0_10px_rgba(148,163,184,0.7)]"
    }`}
  />

  <span
    className={`text-sm font-medium ${
      isPhone
        ? isTrusted
          ? "text-emerald-300"
          : "text-red-300"
        : d.status === "active"
          ? "text-cyan-300"
          : "text-slate-400"
    }`}
  >
    {isPhone
      ? isTrusted
        ? "Trusted"
        : "Revoked"
      : d.status === "active"
        ? "Connected"
        : "Offline"}
  </span>
</div>
                  </div>
                </div>

                <span
                  className={`rounded-full px-3 py-1 text-[10px] ${
                    d.status === "active"
                      ? "bg-emerald-400/10 text-emerald-300"
                      : "bg-red-400/10 text-red-300"
                  }`}
                >
                  {d.status?.toUpperCase() || "ACTIVE"}
                </span>
              </div>

              <div className="mt-5 grid grid-cols-2 gap-3">
                <Info
                  label="Owner"
                  value={
                    d.owner_name || "Ghanaram"
                  }
                />

                <Info
                  label="Authentication"
                  value={
                    d.authentication_method ||
                    (isPhone ? "Passkey" : "PC Agent")
                  }
                />

                <Info
                  label="Device Type"
                  value={
                    d.device_type?.toUpperCase() ||
                    "DEVICE"
                  }
                />

                <Info
                  label="Last Seen"
                  value={
                    d.last_seen
                      ? fmt(d.last_seen)
                      : "--"
                  }
                />
              </div>

              {isPhone && (
                <>
                  <div className="mt-5 flex gap-3">
                    {isTrusted ? (
                      <button
                        onClick={() =>
                          handleAction(
                            d,
                            "revoke"
                          )
                        }
                        disabled={isBusy}
                        className="flex-1 rounded-xl border border-red-300/20 bg-red-400/10 px-4 py-3 text-sm text-red-300 hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {isBusy
                          ? "Revoking..."
                          : "Revoke Device"}
                      </button>
                    ) : (
                      <button
                        onClick={() =>
                          handleAction(
                            d,
                            "retrust"
                          )
                        }
                        disabled={isBusy}
                        className="flex-1 rounded-xl border border-emerald-300/20 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-300 hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {isBusy
                          ? "Re-trusting..."
                          : "Re-Trust Device"}
                      </button>
                    )}
                  </div>

                  <div className="mt-3 text-[10px] text-slate-500">
                    {isTrusted
                      ? "Device can request WebAuthn authorization."
                      : "Authentication is blocked until trust is restored."}
                  </div>
                </>
              )}

            {!isPhone && (
  <div className="mt-5 space-y-3">
    {/* Authorization Status */}
    <div
      className={`rounded-xl border p-4 ${
        d.pc_authorized
          ? "border-emerald-300/20 bg-emerald-400/10"
          : "border-slate-300/10 bg-slate-400/5"
      }`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[10px] uppercase tracking-wider text-slate-500">
            Authorization
          </p>

          <p
            className={`mt-1 text-sm font-semibold ${
              d.pc_authorized
                ? "text-emerald-300"
                : "text-slate-300"
            }`}
          >
            {d.pc_authorized
              ? "● Authorized"
              : "● Locked"}
          </p>
        </div>

        <ShieldCheck
          size={20}
          className={
            d.pc_authorized
              ? "text-emerald-300"
              : "text-slate-500"
          }
        />
      </div>

      {Boolean(d.pc_authorized && d.pc_authorized_device) && (
        <div className="mt-3 border-t border-white/5 pt-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">
            Authorized By
          </p>

          <p className="mt-1 text-xs text-slate-300">
            📱 {d.pc_authorized_device}
          </p>
        </div>
      )}

      {!d.pc_authorized && (
        <p className="mt-2 text-[10px] text-slate-500">
          No active phone authorization.
        </p>
      )}
    </div>

    {/* Agent Information */}
    <div className="rounded-xl border border-cyan-300/10 bg-cyan-300/5 p-4 text-xs text-slate-400">
      <div className="flex items-center gap-2">
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
        PC Agent device
      </div>

      <p className="mt-2">
        Connection and authorization are managed by the BioLock Agent.
      </p>
    </div>
  </div>
)}
            </motion.div>
          );
        })}

        {devices.length === 0 && (
          <div className="glass rounded-2xl p-8 text-center text-slate-500 md:col-span-2">
            No BioLock devices registered.
          </div>
        )}
      </div>
    </div>
  );
}

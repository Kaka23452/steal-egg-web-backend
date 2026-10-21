import express from 'express';
import cors from 'cors';
import { Client, GatewayIntentBits, Partials } from 'discord.js';
const app=express(); const PORT=Number(process.env.PORT||3000);
const CHANNEL_ID=String(process.env.DISCORD_CHANNEL_ID||'').trim(); const BOT_TOKEN=String(process.env.DISCORD_BOT_TOKEN||'').trim();
const ALLOWED_ORIGIN=String(process.env.ALLOWED_ORIGIN||'*').trim();
app.use(cors({origin:ALLOWED_ORIGIN==='*'?true:ALLOWED_ORIGIN.split(',').map(x=>x.trim()),methods:['GET','OPTIONS'],allowedHeaders:['Accept','Content-Type']}));
let spawns=[];let lastMessage=null;let botStatus={connected:false,message:'Discord bot not configured',lastEventAt:null};
function duration(s){s=String(s||'').trim().toLowerCase();let m;if((m=s.match(/^(?:(\d+)\s*d\s*)?(?:(\d+)\s*h\s*)?(?:(\d+)\s*m\s*)?(?:(\d+)\s*s)?$/))&&m.slice(1).some(Boolean))return +(m[1]||0)*86400+ +(m[2]||0)*3600+ +(m[3]||0)*60+ +(m[4]||0);if((m=s.match(/^(\d{1,3}):(\d{1,2})(?::(\d{1,2}))?$/)))return m[3]?+m[1]*3600+ +m[2]*60+ +m[3]:+m[1]*60+ +m[2];return null;}
function parseMessage(content,msg){const out=[];for(const raw of String(content||'').replace(/\*\*/g,'').split(/\r?\n/)){const line=raw.trim();if(!line)continue;let name='',secs=null,m;
 // Explicit "Pet: Name | Timer: 5m", "Name: 1h 5m", "Name spawns in 00:45", "Name — 2m 30s".
 m=line.match(/^pet\s*:\s*(.{2,70}?)\s*(?:\||,|;|—|-)\s*(?:timer|spawn(?:s| time)?|in)\s*:?\s*(.+)$/i);
 if(m){name=m[1].trim();secs=duration(m[2]);}
 if(secs==null){m=line.match(/^(.{2,70}?)\s+(?:spawns?\s+in|spawn\s+in|next spawn\s*(?:in)?|timer\s*[:=])\s*(.+)$/i);if(m){name=m[1].replace(/^[-•*\s]+|[-•*\s]+$/g,'').trim();secs=duration(m[2]);}}
 if(secs==null){m=line.match(/^(.{2,70}?)\s*(?:\||—|–|-)\s*(\d{1,3}:\d{2}(?::\d{2})?|(?:(?:\d+)\s*[dhms]\s*)+)$/i);if(m){name=m[1].trim();secs=duration(m[2]);}}
 if(secs==null){m=line.match(/^(.{2,70}?)\s*:\s*((?:\d+\s*[dhms]\s*)+|\d{1,3}:\d{2}(?::\d{2})?)$/i);if(m){name=m[1].trim();secs=duration(m[2]);}}
 if(name&&secs!=null&&secs>0&&secs<=604800){out.push({petName:name,spawnAt:Date.now()+secs*1000,remainingSeconds:secs,sourceText:line,sourceMessageId:msg.id,sourceChannelId:msg.channelId,sourceTimestamp:msg.createdTimestamp});}
 }return out;}
app.get('/',(_q,r)=>r.type('html').send('<h2>Steal An Egg — Discord Spawn Tracker</h2><p>Backend is running.</p><p><a href="/health">Health</a> · <a href="/api/schedule">Schedule API</a></p>'));
app.get('/health',(_q,r)=>r.json({ok:true,service:'steal-an-egg-discord-tracker',discordConnected:botStatus.connected,bot:botStatus,channelConfigured:!!CHANNEL_ID,activeSchedules:spawns.filter(s=>s.spawnAt>Date.now()).length,lastMessage}));
function scheduleResponse(){const now=Date.now();return {ok:true,updatedAt:now,discordConnected:botStatus.connected,bot:botStatus,channelId:CHANNEL_ID||null,lastMessage:lastMessage?{...lastMessage,authorName:lastMessage.authorName}:null,schedules:spawns.filter(s=>s.spawnAt>now).map(s=>({...s,remainingSeconds:Math.max(0,Math.ceil((s.spawnAt-now)/1000))}))};}
app.get('/api/schedule',(_q,r)=>r.json(scheduleResponse()));
app.get('/api/spawns',(_q,r)=>r.json(scheduleResponse()));
app.listen(PORT,'0.0.0.0',()=>console.log(`HTTP server listening on ${PORT}`));
if(!BOT_TOKEN||!CHANNEL_ID){botStatus={connected:false,message:'Set DISCORD_BOT_TOKEN and DISCORD_CHANNEL_ID in JustRunMy environment variables',lastEventAt:null};console.warn(botStatus.message);}else{
 const client=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMessages,GatewayIntentBits.MessageContent],partials:[Partials.Channel]});
 client.once('ready',()=>{botStatus={connected:true,message:`Logged in as ${client.user.tag}`,lastEventAt:Date.now()};console.log(botStatus.message)});
 client.on('messageCreate',msg=>{if(msg.channelId!==CHANNEL_ID)return;const parsed=parseMessage(msg.content,msg);if(!parsed.length)return;lastMessage={content:String(msg.content||'').slice(0,1800),createdAt:msg.createdTimestamp,authorName:msg.author?.username||'unknown',messageId:msg.id};for(const s of parsed)spawns=[...spawns.filter(old=>old.petName.toLowerCase()!==s.petName.toLowerCase()),s];spawns=spawns.filter(s=>s.spawnAt>Date.now()).slice(-200);botStatus={connected:client.isReady(),message:`Parsed ${parsed.length} spawn timer(s)`,lastEventAt:Date.now()};console.log(`Parsed ${parsed.length} spawn timer(s) from channel message ${msg.id}`)});
 client.on('error',e=>{botStatus={connected:false,message:String(e.message||e),lastEventAt:Date.now()};console.error(e)});client.login(BOT_TOKEN).catch(e=>{botStatus={connected:false,message:`Discord login failed: ${e.message}`,lastEventAt:Date.now()};console.error(e)});
}

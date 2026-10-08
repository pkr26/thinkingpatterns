/** Actual credential/preferences/HTTP with an unlinked Native device capability. */
import React from 'react';
import ReactTestRenderer,{act} from 'react-test-renderer';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import {Text,Switch} from 'react-native';
import {api} from '../../src/api/client';
import {SettingsScreen} from '../../src/screens/SettingsScreen';
import {ThemeProvider} from '../../src/theme';
import {vault} from '../../src/vault';
import {setSecureStoreBackend} from '../../src/secureStore';
import {__resetLocalKeyLifecycleForTests,installLocalDataKey} from '../../src/localWriteGuard';
import {runTestControl} from '../helpers/testControl';
import storage from '../helpers/storageMock';
import * as keychain from '../helpers/keychainMock';
import {setLocale,t as tr} from '../../src/strings';
vi.mock('../../src/store',async original=>({...await original<typeof import('../../src/store')>(),useSession:()=>({touchActivity:()=>{},signOut:()=>api.clearSession()})}));
vi.mock('../../src/nativeFeatures',async original=>({...await original<typeof import('../../src/nativeFeatures')>(),reminderCapability:()=>({available:false,reason:'settings.reasonNotifModule'})}));
vi.mock('../../src/healthkit',async original=>({...await original<typeof import('../../src/healthkit')>(),healthKitCapability:()=>({available:false,reason:'settings.reasonHealthModule'})}));
const USER='a'.repeat(32);let root:ReturnType<typeof ReactTestRenderer.create>|undefined;
function words(){const flat=(v:unknown):string=>Array.isArray(v)?v.map(flat).join(''):typeof v==='string'||typeof v==='number'?String(v):'';return root!.root.findAllByType(Text).map(n=>flat(n.props.children)).join(' ');}
beforeEach(async()=>{vi.restoreAllMocks();setLocale('en');storage.__reset();keychain.__reset();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession('Native missing-capability bearer',USER,'alice');vault.unlock({masterKey:Buffer.alloc(32,1),authKey:Buffer.alloc(32,2),dataKey:Buffer.alloc(32,3)},USER);installLocalDataKey(USER,vault.get().dataKey);vi.stubGlobal('fetch',async(url:string)=>{const path=new URL(url).pathname;let value:unknown;if(path.endsWith('/meta'))value={unlock_days:30,llm_available:false,sharing_available:false,audio_available:false};else if(path.endsWith('/auth/key-envelope'))value={key_scheme:'v1',salt:Buffer.alloc(16).toString('base64'),kdf_params:null,wrapped_data_key:null};else if(path.endsWith('/account/recovery'))value={enabled:false,set_at:null,scheme:'v2'};else if(path.endsWith('/account/llm-consent')||path.endsWith('/account/voice-consent'))value={enabled:false,active_for_current_policy:true};else throw new Error('Unexpected Native capability route '+path);const response=new Response(JSON.stringify(value));Object.defineProperty(response,'url',{value:url});return response;});});
afterEach(async()=>{if(root){await act(async()=>root!.unmount());root=undefined;}vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
it('an unlinked Native notification module disables its controls and explains the concrete capability reason',async()=>{await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SettingsScreen navigation={{navigate:()=>{},popToTop:()=>{}}}/></ThemeProvider>);});await act(async()=>new Promise(resolve=>setTimeout(resolve,0)));expect(words()).toContain(tr('settings.reminderUnavailableNote',{reason:tr('settings.reasonNotifModule')}));for(const label of ['Daily reminder','Check-in reminders'])expect(root!.root.findAllByType(Switch).find(n=>n.props.accessibilityLabel===label)!.props.disabled).toBe(true);});
it('an unlinked Native Health module keeps its preference visible with an honest disabled explanation',async()=>{await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SettingsScreen navigation={{navigate:()=>{},popToTop:()=>{}}}/></ThemeProvider>);});await act(async()=>new Promise(resolve=>setTimeout(resolve,0)));expect(words()).toContain(tr('settings.healthMirrorUnavailableNote',{reason:tr('settings.reasonHealthModule')}));expect(root!.root.findAllByType(Switch).find(n=>n.props.accessibilityLabel==='Mirror mood check-ins to the Health app')!.props.disabled).toBe(true);});

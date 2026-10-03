#!/usr/bin/python3
"""Linux integration test: needs tmux and passwordless sudo for its tmpfs workdir."""
import json,os,subprocess,time,threading
from pathlib import Path
import shutil,uuid
sid='doctor-attach-'+uuid.uuid4().hex[:12];socket='/run/ccdoctor/'+sid+'/tmux.sock'
subprocess.run(['sudo','install','-d','-m','711','/run/ccdoctor'],check=True)
subprocess.run(['sudo','install','-d','-o',str(os.getuid()),'-g',str(os.getgid()),'-m','700','/run/ccdoctor/'+sid],check=True)
helper=str(Path(__file__).resolve().parents[1]/'roles/controlclaw/files/cc-doctor-attach')
subprocess.run(['tmux','-S',socket,'new-session','-d','-s','doctor-'+sid,'cat'],check=True)
def live(pid):
 try:return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[0]!='Z'
 except FileNotFoundError:return False
def children(pid):
 try: result=[int(x) for x in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
 except FileNotFoundError:return []
 return result+sum([children(child) for child in result],[])
try:
 for end in ['eof','term']:
  proc=subprocess.Popen(['python3',helper,sid,'100','30'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  threading.Thread(target=lambda:proc.stdout.read(),daemon=True).start()
  time.sleep(.2)
  assert proc.poll() is None
  initial=subprocess.check_output(['tmux','-S',socket,'list-clients','-F','#{client_width} #{client_height}'],text=True).strip()
  assert initial=='100 30',initial
  duplicate=subprocess.run(['python3',helper,sid,'100','30'],input=b'',capture_output=True,timeout=3)
  assert duplicate.returncode!=0
  proc.stdin.write(json.dumps({'type':'resize','cols':42,'rows':18}).encode()+b'\n');proc.stdin.flush()
  time.sleep(.3)
  size=subprocess.check_output(['tmux','-S',socket,'display-message','-p','-t','doctor-'+sid,'#{window_width} #{window_height}'],text=True).strip()
  assert size=='42 17',size
  client=subprocess.check_output(['tmux','-S',socket,'list-clients','-F','#{client_width} #{client_height}'],text=True).strip()
  assert client=='42 18',client
  proc.stdin.write(json.dumps({'type':'input','data':'DOCTOR_INPUT_PROBE\r'}).encode()+b'\n');proc.stdin.flush()
  time.sleep(.2)
  pane=subprocess.check_output(['tmux','-S',socket,'capture-pane','-p','-t','doctor-'+sid],text=True)
  assert 'DOCTOR_INPUT_PROBE' in pane
  descendants=children(proc.pid)
  assert len(descendants)>=1,descendants
  start=time.monotonic()
  if end=='eof':proc.stdin.close()
  else:proc.terminate()
  proc.wait(timeout=3)
  time.sleep(.1)
  assert not [p for p in descendants if live(p)],descendants
  assert subprocess.run(['tmux','-S',socket,'has-session','-t','doctor-'+sid]).returncode==0
  print(end,': PTY/client/window resized to 42x18; keyboard input delivered; duplicate refused; all',len(descendants),'attachment processes reaped in',round(time.monotonic()-start,2),'seconds; session preserved')
finally:
 subprocess.run(['tmux','-S',socket,'kill-server'])
 shutil.rmtree('/run/ccdoctor/'+sid,ignore_errors=True)
 subprocess.run(['sudo','rmdir','/run/ccdoctor/'+sid],check=True)

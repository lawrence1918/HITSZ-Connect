package auth

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const hitszSliderCaptchaTimeout = 3 * time.Minute

type hitszSliderChallenge struct {
	BigImage   string `json:"bigImage"`
	SmallImage string `json:"smallImage"`
}

type hitszSliderTrack struct {
	A int   `json:"a"`
	B int   `json:"b"`
	C int64 `json:"c"`
}

type hitszSliderAnswer struct {
	CanvasLength int                `json:"canvasLength"`
	MoveLength   int                `json:"moveLength"`
	Tracks       []hitszSliderTrack `json:"tracks"`
}

func (s *Session) hitszOpenSliderChallenge(origin, loginURL string) (hitszSliderChallenge, string, error) {
	req, err := http.NewRequest(http.MethodGet, origin+"/authserver/common/openSliderCaptcha.htl", nil)
	if err != nil {
		return hitszSliderChallenge{}, "", errors.New("build HITSZ slider challenge request")
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", loginURL)
	req.Header.Set("User-Agent", hitszSSOUserAgent)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return hitszSliderChallenge{}, "", errors.New("request HITSZ slider challenge")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return hitszSliderChallenge{}, "", fmt.Errorf("HITSZ slider challenge failed with status %s", resp.Status)
	}
	var challenge hitszSliderChallenge
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&challenge); err != nil {
		return hitszSliderChallenge{}, "", errors.New("parse HITSZ slider challenge")
	}
	if strings.TrimSpace(challenge.BigImage) == "" || strings.TrimSpace(challenge.SmallImage) == "" {
		return hitszSliderChallenge{}, "", errors.New("HITSZ slider challenge has no puzzle images")
	}
	smallImage, err := base64.StdEncoding.DecodeString(challenge.SmallImage)
	if err != nil || len(smallImage) < 16 {
		return hitszSliderChallenge{}, "", errors.New("HITSZ slider challenge has invalid secure data")
	}
	secureKey := string(smallImage[len(smallImage)-16:])
	if len(secureKey) != 16 {
		return hitszSliderChallenge{}, "", errors.New("HITSZ slider challenge has invalid secure key")
	}
	return challenge, secureKey, nil
}

func (s *Session) hitszVerifySlider(origin, loginURL, secureKey string, answer hitszSliderAnswer) (bool, error) {
	if len(secureKey) != 16 || answer.CanvasLength != 280 || answer.MoveLength <= 0 || answer.MoveLength >= 280 || len(answer.Tracks) < 2 || len(answer.Tracks) > 1024 {
		return false, errors.New("invalid HITSZ slider answer")
	}
	payload, err := json.Marshal(answer)
	if err != nil {
		return false, errors.New("encode HITSZ slider answer")
	}
	sign, err := encryptHITSZPassword(string(payload), secureKey)
	if err != nil {
		return false, errors.New("encrypt HITSZ slider answer")
	}
	values := url.Values{"sign": {sign}}
	req, err := http.NewRequest(http.MethodPost, origin+"/authserver/common/verifySliderCaptcha.htl", strings.NewReader(values.Encode()))
	if err != nil {
		return false, errors.New("build HITSZ slider verification request")
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", loginURL)
	req.Header.Set("User-Agent", hitszSSOUserAgent)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return false, errors.New("request HITSZ slider verification")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HITSZ slider verification failed with status %s", resp.Status)
	}
	var result struct {
		ErrorCode int `json:"errorCode"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return false, errors.New("parse HITSZ slider verification response")
	}
	return result.ErrorCode == 1, nil
}

func (s *Session) hitszSolveSliderCaptcha(origin, loginURL string) error {
	tokenBytes := make([]byte, 16)
	if _, err := cryptorand.Read(tokenBytes); err != nil {
		return errors.New("create HITSZ slider browser token")
	}
	token := hex.EncodeToString(tokenBytes)
	basePath := "/" + token + "/"
	solved := make(chan struct{}, 1)

	var challengeMu sync.Mutex
	secureKey := ""
	mux := http.NewServeMux()
	mux.HandleFunc(basePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != basePath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, hitszSliderPageHTML)
	})
	mux.HandleFunc(basePath+"challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		challenge, key, err := s.hitszOpenSliderChallenge(origin, loginURL)
		if err != nil {
			http.Error(w, "unable to load slider challenge", http.StatusBadGateway)
			return
		}
		challengeMu.Lock()
		secureKey = key
		challengeMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(challenge)
	})
	mux.HandleFunc(basePath+"verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var answer hitszSliderAnswer
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&answer); err != nil {
			http.Error(w, "invalid slider answer", http.StatusBadRequest)
			return
		}
		challengeMu.Lock()
		key := secureKey
		challengeMu.Unlock()
		verified, err := s.hitszVerifySlider(origin, loginURL, key, answer)
		if err != nil {
			http.Error(w, "unable to verify slider answer", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": verified})
		if verified {
			select {
			case solved <- struct{}{}:
			default:
			}
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("start local HITSZ slider server")
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	localURL := "http://" + listener.Addr().String() + basePath
	log.Println("HITSZ slider verification opened in the default browser")
	browserOpener := s.hitszSliderBrowserOpener
	if browserOpener == nil {
		browserOpener = openBrowser
	}
	browserOpener(localURL)
	timeout := s.hitszSliderTimeout
	if timeout <= 0 {
		timeout = hitszSliderCaptchaTimeout
	}
	select {
	case <-solved:
		log.Println("HITSZ slider verification completed")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("HITSZ slider verification timed out after %s", timeout)
	}
}

const hitszSliderPageHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HITSZ Connect 安全验证</title>
<style>
body{margin:0;background:#f3f6fa;color:#172033;font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;min-height:100vh}
.card{width:320px;background:#fff;border-radius:16px;box-shadow:0 14px 40px #16345c24;padding:20px}.title{font-size:18px;font-weight:650;margin-bottom:6px}.hint{color:#667085;margin-bottom:16px}
.puzzle{position:relative;width:280px;height:155px;overflow:hidden;border-radius:10px;background:#e8edf4}.puzzle img{user-select:none;-webkit-user-drag:none}.big{width:280px;height:155px}.piece{position:absolute;left:0;top:0;height:155px;width:auto}
.bar{position:relative;width:280px;height:44px;margin-top:14px;background:#eef2f7;border-radius:10px;touch-action:none}.fill{position:absolute;left:0;top:0;height:44px;width:0;background:#d7e9ff;border-radius:10px}.thumb{position:absolute;left:0;top:0;width:42px;height:42px;border:1px solid #c8d0dc;border-radius:10px;background:#fff;box-shadow:0 2px 8px #18223024;display:grid;place-items:center;font-size:22px;cursor:grab}.status{text-align:center;margin-top:12px;min-height:20px;color:#475467}.ok{color:#067647}.bad{color:#b42318}
</style></head><body><main class="card"><div class="title">统一认证安全验证</div><div class="hint">请拖动滑块，使拼图完整。</div>
<div class="puzzle"><img class="big" id="big" alt="拼图背景"><img class="piece" id="piece" alt="拼图片段"></div>
<div class="bar" id="bar"><div class="fill" id="fill"></div><div class="thumb" id="thumb">›</div></div><div class="status" id="status">正在加载…</div></main>
<script>
const width=280,maxMove=240,big=document.getElementById('big'),piece=document.getElementById('piece'),thumb=document.getElementById('thumb'),fill=document.getElementById('fill'),statusEl=document.getElementById('status');
let dragging=false,startX=0,startY=0,lastX=0,lastY=0,lastAt=0,move=0,tracks=[];
function status(text,kind=''){statusEl.textContent=text;statusEl.className='status '+kind}
function setMove(x){move=Math.max(0,Math.min(maxMove,Math.round(x)));thumb.style.left=move+'px';piece.style.left=move+'px';fill.style.width=(move+21)+'px'}
async function loadChallenge(){status('正在加载…');setMove(0);tracks=[];const response=await fetch('challenge',{cache:'no-store'});if(!response.ok)throw new Error('load');const data=await response.json();big.src='data:image/png;base64,'+data.bigImage;piece.src='data:image/png;base64,'+data.smallImage;await Promise.all([big.decode(),piece.decode()]);piece.style.width=(piece.naturalWidth*width/big.naturalWidth)+'px';status('向右拖动滑块完成拼图')}
thumb.addEventListener('pointerdown',event=>{if(dragging)return;dragging=true;thumb.setPointerCapture(event.pointerId);startX=event.clientX;startY=event.clientY;lastX=0;lastY=0;lastAt=Date.now();tracks=[{a:0,b:0,c:0}];status('拖动中…');event.preventDefault()});
thumb.addEventListener('pointermove',event=>{if(!dragging)return;const x=Math.max(0,Math.min(maxMove,event.clientX-startX)),y=Math.round(event.clientY-startY),now=Date.now(),elapsed=now-lastAt;setMove(x);if(elapsed>=20&&Math.hypot(x-lastX,y-lastY)>=2){tracks.push({a:Math.round(x),b:y,c:elapsed});lastX=x;lastY=y;lastAt=now}});
async function finish(event){if(!dragging)return;dragging=false;const x=move,y=Math.round(event.clientY-startY),now=Date.now();tracks.push({a:x,b:y,c:now-lastAt});status('正在验证…');try{const response=await fetch('verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({canvasLength:width,moveLength:x,tracks})});const data=response.ok?await response.json():{ok:false};if(data.ok){status('验证成功，可以返回 HITSZ Connect。','ok');setTimeout(()=>window.close(),900)}else{status('位置不正确，请重试。','bad');setTimeout(()=>loadChallenge().catch(()=>status('加载失败，请刷新页面。','bad')),700)}}catch(_){status('验证失败，请刷新页面重试。','bad')}}
thumb.addEventListener('pointerup',finish);thumb.addEventListener('pointercancel',()=>{dragging=false;setMove(0);status('请重新拖动')});loadChallenge().catch(()=>status('加载失败，请刷新页面。','bad'));
</script></body></html>`

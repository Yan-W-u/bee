import './style.css';

import {GetStatus, Retry, Quit, OpenLogDir} from '../wailsjs/go/main/App';
import {EventsOn} from '../wailsjs/runtime';

const app = document.querySelector('#app');

app.innerHTML = `
  <div class="splash">
    <div class="splash-content">
      <div class="loader" id="loader">
        <div class="status" id="status">准备启动...</div>
        <div class="progress-track">
          <div class="progress-fill" id="progress"></div>
        </div>
        <div class="progress-percent" id="percent">0%</div>
      </div>

      <div class="error-panel" id="errorPanel">
        <div class="error-title" id="errorTitle"></div>
        <pre class="error-detail" id="errorDetail"></pre>
        <div class="error-actions">
          <button class="btn btn-primary" id="retryBtn" style="display:none">重试</button>
          <button class="btn" id="quitBtn">退出</button>
          <button class="btn btn-link" id="logBtn">打开日志目录</button>
        </div>
      </div>
    </div>
  </div>
`;

const statusEl = document.getElementById('status');
const progressEl = document.getElementById('progress');
const percentEl = document.getElementById('percent');
const loaderEl = document.getElementById('loader');
const errorPanel = document.getElementById('errorPanel');
const errorTitle = document.getElementById('errorTitle');
const errorDetail = document.getElementById('errorDetail');
const retryBtn = document.getElementById('retryBtn');
const quitBtn = document.getElementById('quitBtn');
const logBtn = document.getElementById('logBtn');

function renderStatus(s) {
  statusEl.textContent = s.message || '加载中...';
  progressEl.style.width = s.progress + '%';
  percentEl.textContent = s.progress + '%';

  if (s.step === 'error') {
    loaderEl.style.opacity = '0';
    errorPanel.style.display = 'block';
    errorTitle.textContent = s.message || '出错了';
    errorDetail.textContent = s.error || '';
    retryBtn.style.display = s.canRetry ? 'inline-block' : 'none';
  } else {
    loaderEl.style.opacity = '1';
    errorPanel.style.display = 'none';
  }
}

retryBtn.addEventListener('click', () => {
  errorPanel.style.display = 'none';
  Retry();
});

quitBtn.addEventListener('click', () => Quit());
logBtn.addEventListener('click', () => OpenLogDir());

EventsOn('status', (s) => renderStatus(s));

GetStatus().then(renderStatus).catch(console.error);

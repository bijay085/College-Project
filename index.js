const tabs = document.querySelectorAll('.tab-btn');
const contents = document.querySelectorAll('.tab-content');

tabs.forEach(btn => {
    btn.addEventListener('click', () => {
        tabs.forEach(b => b.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    });
});

// Animated file upload progress (demo logic)
const fileInput = document.getElementById('bulkFile');
const progressBar = document.querySelector('.upload-progress-bar');
const progressInner = document.querySelector('.upload-progress-bar-inner');
const bulkResults = document.getElementById('bulkResults');
const bulkSubmit = document.getElementById('bulkSubmit');

if (fileInput && progressBar && progressInner && bulkSubmit) {
    progressBar.classList.add('hidden');
    bulkSubmit.addEventListener('click', function () {
        if (!fileInput.files.length) return;
        progressBar.classList.remove('hidden');
        progressInner.style.width = '0%';
        bulkResults.innerHTML = '';
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 25;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                setTimeout(() => {
                    progressBar.classList.add('hidden');
                    bulkResults.innerHTML = `<div class="summary-box" style="opacity:1;transform:none;">
                <b>Upload Complete!</b><br>
                <span style="color:#0ea5e9;">${fileInput.files[0].name}</span> processed.<br>
                <span style="color:#16a34a;">No fraud detected in your sample file.</span>
              </div>`;
                }, 600);
            }
            progressInner.style.width = progress + '%';
        }, 350);
    });
}

document.addEventListener('DOMContentLoaded', () => {
  // Bulk upload form logic
  const bulkFileInput = document.getElementById('bulkFile');
  const bulkResults = document.getElementById('bulkResults');
  const uploadBox = document.querySelector('.upload-box');
  const progressBar = document.querySelector('.upload-progress-bar-inner');

  // If the upload box uses a form, handle its submit event
  let form = uploadBox.querySelector('form');
  if (!form) {
    // If not, create a form wrapper for the file input
    const input = uploadBox.querySelector('input[type="file"]');
    form = document.createElement('form');
    input.parentNode.insertBefore(form, input);
    form.appendChild(input);
    // Move progress bar and desc into form for better UX
    const progress = uploadBox.querySelector('.upload-progress-bar');
    const desc = uploadBox.querySelector('.upload-desc');
    if (progress) form.appendChild(progress);
    if (desc) form.appendChild(desc);
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    bulkResults.innerHTML = '';
    progressBar.style.width = '0%';

    const file = bulkFileInput.files[0];
    if (!file) {
      bulkResults.textContent = 'Please select a file to upload.';
      return;
    }

    // Simulate loading
    let progress = 0;
    const interval = setInterval(() => {
      progress += 10;
      progressBar.style.width = progress + '%';
      if (progress >= 100) {
        clearInterval(interval);

        // Simulate summary and downloadable result
        const summary = document.createElement('div');
        summary.innerHTML = `
          <h3>Bulk Check Summary</h3>
          <ul>
            <li><strong>File:</strong> ${file.name}</li>
            <li><strong>Type:</strong> ${file.type || 'Unknown'}</li>
            <li><strong>Status:</strong> Processed successfully</li>
            <li><strong>Records:</strong> ${Math.floor(Math.random() * 100) + 10}</li>
          </ul>
        `;

        // Create a fake downloadable result
        const resultData = 'id,status\n1,ok\n2,review\n3,fraud\n';
        const blob = new Blob([resultData], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const downloadLink = document.createElement('a');
        downloadLink.href = url;
        downloadLink.download = 'bulk-results.csv';
        downloadLink.textContent = 'Download Results';
        downloadLink.className = 'submit-btn';
        downloadLink.style.marginTop = '10px';

        bulkResults.innerHTML = '';
        bulkResults.appendChild(summary);
        bulkResults.appendChild(downloadLink);
      }
    }, 80);
  });
});
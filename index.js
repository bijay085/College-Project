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

// ---------------------------------------------------------------------------
// FIXED Bulk-Upload with Proper Button State Management
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // DOM refs
  const fileInput       = document.getElementById('bulkFile');
  const submitBtn       = document.getElementById('bulkSubmit');
  const progressOuter   = document.querySelector('.upload-progress-bar');
  const progressInner   = document.querySelector('.upload-progress-bar-inner');
  const bulkResultsBox  = document.getElementById('bulkResults');
  const fileInfo        = document.getElementById('fileInfo');
  const fileName        = document.getElementById('fileName');
  const fileSize        = document.getElementById('fileSize');
  const uploadBox       = document.getElementById('uploadBox');

  // Hide progress bar initially
  if (progressOuter) progressOuter.classList.add('hidden');

  // Validate file function
  function validateFile(file) {
    if (!file) {
      return { valid: false, message: "No file selected" };
    }

    // Check file extension
    const allowedExtensions = ['csv', 'json', 'xlsx', 'xls', 'txt'];
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedExtensions.includes(extension)) {
      return { 
        valid: false, 
        message: `File type not supported. Allowed: ${allowedExtensions.join(', ')}` 
      };
    }

    // Check file size (16MB limit)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
      return { 
        valid: false, 
        message: `File too large. Maximum: 16MB. Your file: ${(file.size / (1024*1024)).toFixed(1)}MB` 
      };
    }

    if (file.size === 0) {
      return { valid: false, message: "File is empty" };
    }

    return { valid: true, message: "File is valid" };
  }

  // Format file size for display
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // Update button state and text
  function updateButtonState(file) {
    if (!file) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Select a file first';
      submitBtn.style.cursor = 'not-allowed';
      submitBtn.style.opacity = '0.6';
      return;
    }

    const validation = validateFile(file);
    
    if (validation.valid) {
      // Enable button for valid files
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <span class="btn-icon">🔍</span>
        <span class="btn-text">Analyze ${file.name}</span>
      `;
      submitBtn.style.cursor = 'pointer';
      submitBtn.style.opacity = '1';
      submitBtn.style.background = 'linear-gradient(135deg, var(--primary), var(--primary-light))';
      
      // Show file info
      if (fileName) fileName.textContent = file.name;
      if (fileSize) fileSize.textContent = formatFileSize(file.size);
      if (fileInfo) fileInfo.classList.remove('hidden');
      
    } else {
      // Disable button for invalid files
      submitBtn.disabled = true;
      submitBtn.innerHTML = `
        <span class="btn-icon">❌</span>
        <span class="btn-text">${validation.message}</span>
      `;
      submitBtn.style.cursor = 'not-allowed';
      submitBtn.style.opacity = '0.6';
      submitBtn.style.background = '#dc2626';
      
      // Hide file info
      if (fileInfo) fileInfo.classList.add('hidden');
    }
  }

  // File input change handler
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    updateButtonState(file);
    
    // Clear previous results
    if (bulkResultsBox) bulkResultsBox.innerHTML = '';
  });

  // Drag and drop functionality
  if (uploadBox) {
    uploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--primary)';
      uploadBox.style.backgroundColor = 'rgba(37, 99, 235, 0.05)';
    });

    uploadBox.addEventListener('dragleave', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--gray-300)';
      uploadBox.style.backgroundColor = '';
    });

    uploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--gray-300)';
      uploadBox.style.backgroundColor = '';
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        fileInput.files = files;
        const event = new Event('change', { bubbles: true });
        fileInput.dispatchEvent(event);
      }
    });
  }

  // Initialize button state
  updateButtonState(null);

  // --- Helper to render server results ------------------------------------
  function renderResults(results, summary = null) {
    const ok   = results.filter(r => r.decision === 'not_fraud').length;
    const sus  = results.filter(r => r.decision === 'suspicious').length;
    const bad  = results.filter(r => r.decision === 'fraud').length;
    const errors = results.filter(r => r.decision === 'error').length;

    const summaryText = summary ? `
      <div style="margin-bottom: 16px; padding: 12px; background: #f1f5f9; border-radius: 8px; font-size: 0.9rem;">
        📁 <strong>${summary.filename || 'Unknown file'}</strong><br>
        ⏱️ Processing time: ${summary.processing_time_seconds || 0}s<br>
        📊 Total records: ${summary.total_records || results.length}
      </div>
    ` : '';

    bulkResultsBox.innerHTML = `
      ${summaryText}
      <div class="summary-box">
        <b>Analysis Complete</b>
        Total transactions: ${results.length}<br>
        <span style="color:#059669;">✅ Safe: ${ok}</span><br>
        <span style="color:#d97706;">⚠️ Suspicious: ${sus}</span><br>
        <span style="color:#dc2626;">❌ Fraud: ${bad}</span><br>
        ${errors > 0 ? `<span style="color:#6b7280;">❓ Errors: ${errors}</span><br>` : ''}
        <br>
        <button id="dlCsv" class="secondary-btn">📥 Download Results</button>
      </div>
    `;

    // CSV download functionality
    document.getElementById('dlCsv').onclick = () => {
      try {
        const headers = Object.keys(results[0] || {});
        const csv = [
          headers.join(','),
          ...results.map(r => headers.map(h => {
            let value = r[h];
            if (Array.isArray(value)) {
              value = value.join(';');
            }
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
              value = `"${value.replace(/"/g, '""')}"`;
            }
            return value || '';
          }).join(','))
        ].join('\n');
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url;
        a.download = `fraudshield_results_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } catch (error) {
        alert('Error generating CSV: ' + error.message);
      }
    };
  }

  // --- Enhanced table rendering ----------------------
  function renderTable(results) {
    let sortKey = null;
    let sortAsc = true;
    let sortedResults = [...results];

    const headers = [
      { label: "#", key: null },
      { label: "Email", key: "email" },
      { label: "Card", key: "card_number" },
      { label: "IP", key: "ip" },
      { label: "Fingerprint", key: "fingerprint" },
      { label: "Price", key: "price" },
      { label: "Decision", key: "decision" },
      { label: "Score", key: "fraud_score" },
      { label: "Triggered", key: "triggered_rules" }
    ];

    const tableContainer = document.createElement('div');
    tableContainer.className = 'table-container';
    
    const table = document.createElement('table');
    table.classList.add('bulk-table');

    // Table Head
    const thead = table.createTHead();
    const headRow = thead.insertRow();
    headers.forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h.label;
      if (h.key) {
        th.style.cursor = "pointer";
        th.title = "Click to sort by " + h.label;
        th.classList.add('sortable');
        th.onclick = () => {
          // Remove previous sort indicators
          document.querySelectorAll('th.sortable').forEach(header => {
            header.classList.remove('sort-asc', 'sort-desc');
          });
          
          if (sortKey === h.key) {
            sortAsc = !sortAsc;
          } else {
            sortKey = h.key;
            sortAsc = true;
          }
          
          // Add sort indicator
          th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
          
          sortedResults.sort((a, b) => {
            let va = a[h.key], vb = b[h.key];
            
            if (h.key === "fraud_score" || h.key === "price") {
              va = parseFloat(va) || 0;
              vb = parseFloat(vb) || 0;
            } else if (Array.isArray(va)) {
              va = va.join(",");
              vb = Array.isArray(vb) ? vb.join(",") : "";
            } else {
              va = String(va || "").toLowerCase();
              vb = String(vb || "").toLowerCase();
            }
            
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
          });
          
          renderBody();
        };
      }
      headRow.appendChild(th);
    });

    // Table Body
    const tbody = table.createTBody();
    function renderBody() {
      tbody.innerHTML = "";
      sortedResults.forEach((r, idx) => {
        const row = tbody.insertRow();
        row.className = `decision-row decision-${r.decision}`;
        
        const triggeredRules = Array.isArray(r.triggered_rules) 
          ? r.triggered_rules.join(", ") 
          : (r.triggered_rules || "-");
        
        row.innerHTML = `
          <td class="center">${idx + 1}</td>
          <td title="${r.email || ''}">${r.email || '-'}</td>
          <td title="${r.card_number || ''}">${r.card_number || '-'}</td>
          <td title="${r.ip || ''}">${r.ip || '-'}</td>
          <td title="${r.fingerprint || ''}">${r.fingerprint || '-'}</td>
          <td class="center">$${r.price || '0'}</td>
          <td class="center">
            <span class="status-indicator status-${r.decision === 'not_fraud' ? 'safe' : r.decision}">
              ${r.decision || 'unknown'}
            </span>
          </td>
          <td class="center"><strong>${r.fraud_score || '0'}</strong></td>
          <td title="${triggeredRules}">${triggeredRules}</td>
        `;
      });
    }
    renderBody();

    tableContainer.appendChild(table);
    return tableContainer;
  }

  // --- Main form submission handler -------------------
  submitBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    
    const file = fileInput.files[0];
    
    // Double-check validation
    const validation = validateFile(file);
    if (!validation.valid) {
      alert(validation.message);
      return;
    }
    
    // Reset UI
    bulkResultsBox.innerHTML = '';
    if (progressOuter) progressOuter.classList.remove('hidden');
    if (progressInner) progressInner.style.width = '0%';
    
    // Update button to loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="loading"></span>
      <span class="btn-text">Processing...</span>
    `;

    const formData = new FormData();
    formData.append('file', file);

    try {
      console.log('Sending request to bulk-check API...');
      
      const response = await fetch('http://127.0.0.1:5000/bulk-check', {
        method: 'POST',
        body: formData,
      });

      if (progressInner) progressInner.style.width = '50%';

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', response.status, errorText);
        throw new Error(`Server error (${response.status}): ${errorText}`);
      }

      const responseData = await response.json();
      console.log('API Response:', responseData);

      if (progressInner) progressInner.style.width = '100%';

      if (!responseData.success) {
        throw new Error(responseData.error || 'API returned failure status');
      }

      const results = responseData.data?.results;
      const summary = responseData.data?.summary;

      if (!results || !Array.isArray(results)) {
        console.error('Invalid response structure:', responseData);
        throw new Error('Invalid response format: results not found');
      }

      if (results.length === 0) {
        bulkResultsBox.innerHTML = '<div style="color: #6b7280; padding: 16px; text-align: center;">ℹ️ No data found in the uploaded file.</div>';
        return;
      }

      console.log(`Processing ${results.length} results...`);

      // Render results
      bulkResultsBox.innerHTML = "<h3>Fraud Analysis Results</h3>";
      bulkResultsBox.appendChild(renderTable(results));

      // Add summary after table
      setTimeout(() => {
        renderResults(results, summary);
        bulkResultsBox.appendChild(renderTable(results));
      }, 100);

    } catch (err) {
      console.error('Request failed:', err);
      if (progressInner) progressInner.style.width = '0%';
      
      let errorMessage = 'Unknown error occurred';
      if (err.message) {
        errorMessage = err.message;
      } else if (err.name === 'TypeError' && err.message.includes('fetch')) {
        errorMessage = 'Cannot connect to server. Make sure the Flask API is running on http://127.0.0.1:5000';
      }

      bulkResultsBox.innerHTML = `
        <div style="color: #dc2626; padding: 20px; text-align: center; background: #fee2e2; border-radius: 8px; margin: 16px 0;">
          <strong>❌ Error:</strong><br>
          ${errorMessage}
          <br><br>
          <small style="color: #7f1d1d;">
            Check the browser console (F12) for more details.
          </small>
        </div>
      `;
    } finally {
      // Reset button state
      setTimeout(() => {
        if (progressOuter) progressOuter.classList.add('hidden');
        updateButtonState(fileInput.files[0]); // Restore proper button state
      }, 1000);
    }
  });

  // Utility function for tab switching
  window.switchToTab = function(tabName) {
    const tabBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (tabBtn) {
      tabBtn.click();
    }
  };
});
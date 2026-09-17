(function () {
    'use strict';

    var dropZone = document.getElementById('drop-zone');
    var fileInput = document.getElementById('file-input');
    var previewArea = document.getElementById('preview-area');
    var uploadBtn = document.getElementById('upload-btn');
    var form = document.getElementById('upload-form');
    var selectedFiles = [];

    if (!dropZone || !fileInput) return;

    function addFiles(files) {
        for (var i = 0; i < files.length; i++) {
            if (files[i].type.startsWith('image/')) {
                selectedFiles.push(files[i]);
            }
        }
        updatePreviews();
        updateButton();
    }

    function updatePreviews() {
        previewArea.innerHTML = '';
        if (selectedFiles.length === 0) {
            previewArea.classList.add('hidden');
            return;
        }
        previewArea.classList.remove('hidden');
        selectedFiles.forEach(function (file, idx) {
            var item = document.createElement('div');
            item.className = 'preview-item';

            var img = document.createElement('img');
            img.src = URL.createObjectURL(file);
            img.onload = function () { URL.revokeObjectURL(img.src); };

            var removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'preview-remove';
            removeBtn.innerHTML = '<i data-lucide="x"></i>';
            removeBtn.addEventListener('click', function () {
                selectedFiles.splice(idx, 1);
                updatePreviews();
                updateButton();
            });

            item.appendChild(img);
            item.appendChild(removeBtn);
            previewArea.appendChild(item);
        });
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    function updateButton() {
        uploadBtn.disabled = selectedFiles.length === 0;
        var span = uploadBtn.querySelector('span');
        if (span) {
            if (selectedFiles.length === 0) {
                span.textContent = 'Upload';
            } else if (selectedFiles.length === 1) {
                span.textContent = 'Upload 1 image';
            } else {
                span.textContent = 'Upload ' + selectedFiles.length + ' images';
            }
        }
    }

    dropZone.addEventListener('dragover', function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            addFiles(e.dataTransfer.files);
        }
    });

    fileInput.addEventListener('change', function () {
        if (fileInput.files.length > 0) {
            addFiles(fileInput.files);
        }
    });

    document.addEventListener('paste', function (e) {
        var items = (e.clipboardData || e.originalEvent.clipboardData).items;
        var imageFiles = [];
        for (var i = 0; i < items.length; i++) {
            if (items[i].type.startsWith('image/')) {
                var file = items[i].getAsFile();
                if (file) imageFiles.push(file);
            }
        }
        if (imageFiles.length > 0) {
            e.preventDefault();
            addFiles(imageFiles);
        }
    });

    form.addEventListener('submit', function (e) {
        if (selectedFiles.length === 0) {
            e.preventDefault();
            return;
        }
        e.preventDefault();

        var formData = new FormData(form);
        formData.delete('files');
        selectedFiles.forEach(function (file) {
            formData.append('files', file);
        });

        uploadBtn.disabled = true;
        var span = uploadBtn.querySelector('span');
        if (span) span.textContent = 'Uploading...';

        fetch('/upload', {
            method: 'POST',
            body: formData,
        })
            .then(function (response) {
                return response.text();
            })
            .then(function (html) {
                document.open();
                document.write(html);
                document.close();
            })
            .catch(function (err) {
                uploadBtn.disabled = false;
                if (span) span.textContent = 'Upload failed, try again';
                console.error(err);
            });
    });
})();

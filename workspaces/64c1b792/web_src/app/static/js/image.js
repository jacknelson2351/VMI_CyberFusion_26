(function () {
    'use strict';

    // Vote handling
    var voteControls = document.querySelector('.vote-controls');
    if (voteControls) {
        var code = voteControls.dataset.code;
        var scoreEl = document.getElementById('vote-score');
        var buttons = voteControls.querySelectorAll('.btn-vote');

        buttons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                if (btn.disabled) return;
                var value = parseInt(btn.dataset.value, 10);
                var formData = new FormData();
                formData.append('value', value);

                fetch('/api/v1/images/' + code + '/vote', {
                    method: 'POST',
                    body: formData,
                })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        scoreEl.textContent = data.score;
                        buttons.forEach(function (b) { b.classList.remove('active'); });
                        if (data.status === 'voted') {
                            btn.classList.add('active');
                        }
                    })
                    .catch(console.error);
            });
        });
    }

    // Copy link
    var copyBtn = document.getElementById('btn-copy-link');
    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            var text = copyBtn.dataset.copy;
            navigator.clipboard.writeText(text).then(function () {
                var span = copyBtn.querySelector('span') || copyBtn;
                var original = span.textContent;
                span.textContent = 'Copied!';
                setTimeout(function () { span.textContent = original; }, 2000);
            });
        });
    }

    // Comment form
    var commentForm = document.getElementById('comment-form');
    if (commentForm) {
        var code = commentForm.dataset.code;
        var commentsList = document.getElementById('comments-list');

        commentForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var textarea = commentForm.querySelector('textarea');
            var body = textarea.value.trim();
            if (!body) return;

            var formData = new FormData();
            formData.append('body', body);

            fetch('/api/v1/images/' + code + '/comment', {
                method: 'POST',
                body: formData,
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    var comment = document.createElement('div');
                    comment.className = 'comment';
                    comment.style.animation = 'fadeIn 0.3s ease';
                    comment.innerHTML =
                        '<div class="comment-header">' +
                        '<a href="/u/' + escapeHtml(data.author_name) + '" class="comment-author">' +
                        '<i data-lucide="user"></i> ' + escapeHtml(data.author_name) +
                        '</a>' +
                        '<time class="comment-time">Just now</time>' +
                        '</div>' +
                        '<p class="comment-body">' + escapeHtml(data.body) + '</p>';
                    commentsList.insertBefore(comment, commentsList.firstChild);
                    textarea.value = '';
                    if (typeof lucide !== 'undefined') lucide.createIcons();
                })
                .catch(console.error);
        });
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
    }
})();

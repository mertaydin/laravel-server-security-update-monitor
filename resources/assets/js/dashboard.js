(function () {
    'use strict';

    function applyTheme(theme) {
        var prefersDark = window.matchMedia
            && window.matchMedia('(prefers-color-scheme: dark)').matches;
        var isDark = theme === 'dark' || (theme === 'system' && prefersDark);

        document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
    }

    var theme = 'system';
    try {
        theme = window.localStorage.getItem('ssum-theme') || 'system';
    } catch (error) {
        // Theme switching still works for this page when storage is unavailable.
    }
    applyTheme(theme);

    function initializeDashboard() {
        var languageForm = document.getElementById('language-form');
        var languageSelect = document.getElementById('language-select');

        if (languageForm && languageSelect) {
            languageSelect.addEventListener('change', function () {
                if (typeof languageForm.requestSubmit === 'function') {
                    languageForm.requestSubmit();
                } else {
                    languageForm.submit();
                }
            });
        }

        var themeSelect = document.getElementById('theme-select');
        if (themeSelect) {
            themeSelect.value = theme;
            themeSelect.addEventListener('change', function () {
                theme = this.value;
                try {
                    window.localStorage.setItem('ssum-theme', theme);
                } catch (error) {
                    // Do not prevent the visible theme from changing.
                }
                applyTheme(theme);
            });
        }

        var aptUpdateForm = document.getElementById('apt-update-form');
        var refreshLink = document.getElementById('refresh-dashboard');
        var overlay = document.getElementById('scan-loading');

        if (aptUpdateForm && overlay) {
            aptUpdateForm.addEventListener('submit', function (event) {
                if (aptUpdateForm.dataset.loading === 'true') {
                    event.preventDefault();
                    return;
                }

                event.preventDefault();
                aptUpdateForm.dataset.loading = 'true';

                var button = document.getElementById('apt-update-button');
                if (button) {
                    button.disabled = true;
                    button.setAttribute('aria-disabled', 'true');
                }

                var title = overlay.querySelector('.loading-dialog h2');
                var help = overlay.querySelector('.loading-dialog p');
                if (title && overlay.dataset.updateTitle) { title.textContent = overlay.dataset.updateTitle; }
                if (help && overlay.dataset.updateHelp) { help.textContent = overlay.dataset.updateHelp; }

                overlay.classList.add('is-visible');
                overlay.setAttribute('aria-hidden', 'false');
                window.getComputedStyle(overlay).opacity;
                window.requestAnimationFrame(function () {
                    window.requestAnimationFrame(function () {
                        aptUpdateForm.submit();
                    });
                });
            });
        }

        if (refreshLink && overlay) {
            refreshLink.addEventListener('click', function (event) {
                event.preventDefault();

                if (refreshLink.dataset.loading === 'true') {
                    return;
                }

                refreshLink.dataset.loading = 'true';
                refreshLink.setAttribute('aria-disabled', 'true');
                overlay.classList.add('is-visible');
                overlay.setAttribute('aria-hidden', 'false');

                // Force style/layout calculation, then allow the browser to paint.
                window.getComputedStyle(overlay).opacity;
                window.requestAnimationFrame(function () {
                    window.requestAnimationFrame(function () {
                        window.location.assign(refreshLink.href);
                    });
                });
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeDashboard, { once: true });
    } else {
        initializeDashboard();
    }
})();

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
            aptUpdateForm.addEventListener('submit', function () {
                var button = document.getElementById('apt-update-button');
                if (button) {
                    button.disabled = true;
                    button.dataset.loading = 'true';
                }
                overlay.classList.add('is-visible');
                overlay.setAttribute('aria-hidden', 'false');
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

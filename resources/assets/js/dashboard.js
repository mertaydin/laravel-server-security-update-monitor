(function () {
    'use strict';

    function applyTheme(theme) {
        var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.dataset.theme = theme === 'dark' || (theme === 'system' && prefersDark) ? 'dark' : 'light';
    }

    var theme = 'system';
    try { theme = window.localStorage.getItem('ssum-theme') || 'system'; } catch (error) {}
    applyTheme(theme);

    function initializeDashboard() {
        var languageForm = document.getElementById('language-form');
        var languageSelect = document.getElementById('language-select');
        if (languageForm && languageSelect) {
            languageSelect.addEventListener('change', function () {
                if (typeof languageForm.requestSubmit === 'function') languageForm.requestSubmit();
                else languageForm.submit();
            });
        }

        var themeSelect = document.getElementById('theme-select');
        if (themeSelect) {
            themeSelect.value = theme;
            themeSelect.addEventListener('change', function () {
                theme = this.value;
                try { window.localStorage.setItem('ssum-theme', theme); } catch (error) {}
                applyTheme(theme);
            });
        }

        var rows = Array.prototype.slice.call(document.querySelectorAll('#package-table-body tr'));
        var search = document.getElementById('package-search');
        var security = document.getElementById('security-filter');
        var severity = document.getElementById('severity-filter');
        var empty = document.getElementById('no-filter-results');

        function filterPackages() {
            var query = (search ? search.value : '').trim().toLowerCase();
            var securityValue = security ? security.value : 'all';
            var severityValue = severity ? severity.value : 'all';
            var visible = 0;
            rows.forEach(function (row) {
                var matches = (!query || row.dataset.package.indexOf(query) !== -1)
                    && (securityValue === 'all' || row.dataset.security === securityValue)
                    && (severityValue === 'all' || row.dataset.severity === severityValue);
                row.hidden = !matches;
                if (matches) visible++;
            });
            if (empty) empty.hidden = visible !== 0;
        }
        [search, security, severity].forEach(function (control) {
            if (control) control.addEventListener('input', filterPackages);
            if (control && control.tagName === 'SELECT') control.addEventListener('change', filterPackages);
        });

        var aptUpdateForm = document.getElementById('apt-update-form');
        var refreshLink = document.getElementById('refresh-dashboard');
        var overlay = document.getElementById('scan-loading');

        if (aptUpdateForm && overlay) {
            aptUpdateForm.addEventListener('submit', function (event) {
                if (aptUpdateForm.dataset.loading === 'true') { event.preventDefault(); return; }
                event.preventDefault();
                aptUpdateForm.dataset.loading = 'true';
                var button = document.getElementById('apt-update-button');
                if (button) { button.disabled = true; button.setAttribute('aria-disabled', 'true'); }
                var title = overlay.querySelector('.loading-dialog h2');
                var help = overlay.querySelector('.loading-dialog p');
                if (title && overlay.dataset.updateTitle) title.textContent = overlay.dataset.updateTitle;
                if (help && overlay.dataset.updateHelp) help.textContent = overlay.dataset.updateHelp;
                overlay.classList.add('is-visible');
                overlay.setAttribute('aria-hidden', 'false');
                window.getComputedStyle(overlay).opacity;
                window.requestAnimationFrame(function () { window.requestAnimationFrame(function () { aptUpdateForm.submit(); }); });
            });
        }

        if (refreshLink && overlay) {
            refreshLink.addEventListener('click', function (event) {
                event.preventDefault();
                if (refreshLink.dataset.loading === 'true') return;
                refreshLink.dataset.loading = 'true';
                refreshLink.setAttribute('aria-disabled', 'true');
                overlay.classList.add('is-visible');
                overlay.setAttribute('aria-hidden', 'false');
                window.getComputedStyle(overlay).opacity;
                window.requestAnimationFrame(function () { window.requestAnimationFrame(function () { window.location.assign(refreshLink.href); }); });
            });
        }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeDashboard, { once: true });
    else initializeDashboard();
})();

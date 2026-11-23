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

/* Copy-only package upgrade guidance. This never executes a package-manager command. */
(function () {
    'use strict';
    function initializeUpdateCommandCopy() {
        var toolbar = document.querySelector('.toolbar');
        if (!toolbar || toolbar.querySelector('[data-copy-update-command]')) return;
        var manager = (document.querySelector('.top .sub')?.textContent || '').toUpperCase();
        var command;
        if (manager.indexOf('APT') !== -1) command = 'sudo apt-get upgrade';
        else if (manager.indexOf('DNF5') !== -1 || manager.indexOf('DNF') !== -1) command = 'sudo dnf upgrade';
        else if (manager.indexOf('YUM') !== -1) command = 'sudo yum update';
        else return;
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn';
        button.dataset.copyUpdateCommand = 'true';
        button.textContent = 'Copy update command';
        button.addEventListener('click', async function () {
            try {
                if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(command);
                else {
                    var field = document.createElement('textarea');
                    field.value = command;
                    field.style.position = 'fixed';
                    field.style.opacity = '0';
                    document.body.appendChild(field);
                    field.select();
                    var copied = document.execCommand('copy');
                    field.remove();
                    if (!copied) throw new Error('Clipboard unavailable');
                }
                button.textContent = 'Copied: ' + command;
            } catch (error) {
                button.textContent = 'Copy failed';
            }
            window.setTimeout(function () { button.textContent = 'Copy update command'; }, 2200);
        });
        toolbar.appendChild(button);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeUpdateCommandCopy, {once: true});
    else initializeUpdateCommandCopy();
})();

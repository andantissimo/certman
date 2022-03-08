/// <reference path="./index.d.ts" />

document.addEventListener('DOMContentLoaded', () => {
    const dateFormat = new Intl.DateTimeFormat('eo', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour12: false, hour: '2-digit', minute: '2-digit',
    });

    /** @type {HTMLFormElement} */
    const $cas = document.querySelector('form[name="cas"]');
    /** @type {HTMLFormElement} */
    const $certs = document.querySelector('form[name="certs"]');
    const $aside = $certs.querySelector('aside');
    const $crt = $aside.querySelector('.crt');
    const $key = $aside.querySelector('.key');

    document.querySelectorAll('pre').forEach(pre => {
        pre.addEventListener('focus', e => {
            e.preventDefault();
            const range = document.createRange();
            range.selectNodeContents(pre);
            const selection = getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
        });
    });

    $cas.addEventListener('submit', async e => {
        e.preventDefault();
        /** @type {HTMLInputElement} */
        const $cn = $cas.elements.namedItem('cn');
        if (!/^[^"#+,;<=>]+$/.test($cn.value))
            $cn.select();
        else {
            const res = await fetch('pki/ca', {
                method: 'POST',
                body: new URLSearchParams({
                    cn: $cn.value,
                }),
            });
            if (!res.ok)
                $cn.select();
            else {
                $cn.value = '';
                await updateCAs(await res.text());
            }
        }
    });

    $certs.addEventListener('submit', async e => {
        e.preventDefault();
        /** @type {HTMLInputElement} */
        const $ca = $cas.elements.namedItem('ca');
        /** @type {HTMLInputElement} */
        const $cn = $certs.elements.namedItem('cn');
        if (!/^[^"#+,;<=>]+$/.test($cn.value))
            $cn.select();
        else {
            const res = await fetch(`pki/${$ca.value}`, {
                method: 'POST',
                body: new URLSearchParams({
                    cn: $cn.value,
                }),
            });
            if (!res.ok)
                $cn.select();
            else {
                $cn.value = '';
                await updateCertificates(await res.text());
            }
        }
    });

    /** @param {string} [thumbprint] */
    const updateCAs = async (thumbprint) => {
        const now = Date.now();
        $certs.classList.add('hidden');
        /** @type {Certificate[]} */
        const cas = await (await fetch('pki/ca')).json();
        const $tbody = $cas.querySelector('table').tBodies.item(0);
        $tbody.innerHTML = '';
        for (const ca of cas) {
            const $tr = $tbody.insertRow();
            if (Date.parse(ca.notAfter) < now)
                $tr.classList.add('expired');
            const $radio = $tr.insertCell().appendChild(document.createElement('input'));
            $radio.type = 'radio', $radio.name = 'ca', $radio.id = $radio.value = ca.thumbprint;
            $radio.addEventListener('change', _ => updateCertificates());
            if (ca.thumbprint === thumbprint)
                $radio.click();
            const $label = $tr.insertCell().appendChild(document.createElement('label'));
            $label.htmlFor = $radio.id, $label.textContent = ca.subject;
            $tr.insertCell().textContent = dateFormat.format(new Date(ca.notBefore));
            $tr.insertCell().textContent = dateFormat.format(new Date(ca.notAfter));
            const $icons = $tr.insertCell();
            const $crt = $icons.appendChild(document.createElement('a'));
            const $key = $icons.appendChild(document.createElement('a'));
            const $del = $icons.appendChild(document.createElement('a'));
            $crt.textContent = '📄', $crt.title = 'Certificate', $crt.href = `pki/${ca.thumbprint}.crt`;
            $key.textContent = '🔑', $key.title = 'Private Key', $key.href = `pki/${ca.thumbprint}.key`;
            $del.textContent = '🗑', $del.title = 'Delete', $del.href = '';
            $del.addEventListener('click', e => {
                e.preventDefault();
                if (confirm('Are you sure you want to delete this CA?'))
                    fetch(`pki/${ca.thumbprint}`, { method: 'DELETE' }).then(_ => updateCAs());
            });
        }
    };

    /** @param {string} [thumbprint] */
    const updateCertificates = async (thumbprint) => {
        const now = Date.now();
        $aside.classList.add('hidden');
        /** @type {HTMLInputElement} */
        const $ca = document.querySelector('input[name="ca"]:checked');
        if (!$ca)
            return;
        /** @type {Certificate[]} */
        const certs = await (await fetch(`pki/${$ca.value}`)).json();
        const $tbody = $certs.querySelector('table').tBodies.item(0);
        $tbody.innerHTML = '';
        for (const cert of certs) {
            const $tr = $tbody.insertRow();
            if (Date.parse(cert.notAfter) < now)
                $tr.classList.add('expired');
            const $radio = $tr.insertCell().appendChild(document.createElement('input'));
            $radio.type = 'radio', $radio.name = 'cert', $radio.id = $radio.value = cert.thumbprint;
            $radio.addEventListener('change', _ => showCertificate());
            if (cert.thumbprint === thumbprint)
                $radio.click();
            const $label = $tr.insertCell().appendChild(document.createElement('label'));
            $label.htmlFor = $radio.id, $label.textContent = cert.subject;
            $tr.insertCell().textContent = dateFormat.format(new Date(cert.notBefore));
            $tr.insertCell().textContent = dateFormat.format(new Date(cert.notAfter));
            const $icons = $tr.insertCell();
            const $crt = $icons.appendChild(document.createElement('a'));
            const $key = $icons.appendChild(document.createElement('a'));
            const $del = $icons.appendChild(document.createElement('a'));
            $crt.textContent = '📄', $crt.title = 'Certificate', $crt.href = `pki/${cert.thumbprint}.crt`;
            $key.textContent = '🔑', $key.title = 'Private Key', $key.href = `pki/${cert.thumbprint}.key`;
            $del.textContent = '🗑', $del.title = 'Delete', $del.href = '';
            $del.addEventListener('click', e => {
                e.preventDefault();
                if (confirm('Are you sure you want to delete this certificate?'))
                    fetch(`pki/${cert.thumbprint}`, { method: 'DELETE' }).then(_ => updateCertificates());
            });
        }
        $certs.classList.remove('hidden');
    };

    const showCertificate = async () => {
        const $cert = $certs.querySelector('input[name="cert"]:checked');
        if (!$cert)
            return;
        const [crt, key] = await Promise.all([
            fetch(`pki/${$cert.value}.crt`).then(res => res.text()),
            fetch(`pki/${$cert.value}.key`).then(res => res.text()),
        ]);
        $crt.textContent = crt.trim();
        $key.textContent = key.trim();
        $aside.classList.remove('hidden');
    };

    updateCAs();
});

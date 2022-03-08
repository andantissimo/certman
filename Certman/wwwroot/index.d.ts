interface Certificate {
    subject: string;
    notAfter: string;
    notBefore: string;
    thumbprint: string;
    subjectAltName?: string[];
}

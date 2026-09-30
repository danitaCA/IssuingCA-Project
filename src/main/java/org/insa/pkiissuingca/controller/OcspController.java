package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.service.OcspService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * OCSP responder (RFC 6960).
 * POST is implemented per §A.1 (mandatory). The GET variant (§A.1, optional,
 * used for HTTP caching proxies in front of OCSP) is intentionally deferred —
 * add later only if a caching reverse proxy is placed in front of this endpoint.
 */
@RestController
@RequestMapping("/api/v1/ocsp")
public class OcspController {

    private static final String OCSP_REQUEST_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";

    @Autowired
    private OcspService ocspService;

    /**
     * RFC 6960 standard binary OCSP responder endpoint (POST).
     *
     * @param caSerialNumber Serial number of the issuing CA
     * @param requestBytes   DER-encoded OCSPReq payload
     * @return DER-encoded OCSPResp payload
     */
    @PostMapping(
            value = "/{caSerialNumber}",
            consumes = {OCSP_REQUEST_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE, "*/*"},
            produces = {OCSP_RESPONSE_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE}
    )
    // @PreAuthorize("permitAll()")
    public ResponseEntity<byte[]> handleOcspPost(
            @PathVariable String caSerialNumber,
            @RequestBody byte[] requestBytes) {

        byte[] responseDer = ocspService.processOcspRequest(requestBytes, caSerialNumber);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, OCSP_RESPONSE_TYPE)
                .body(responseDer);
    }

    /**
     * RFC 6960 GET variant for HTTP caching proxies.
     * Note: Expects URL-safe or standard Base64-encoded OCSP request.
     *
     * @param caSerialNumber Serial number of the issuing CA
     * @param base64Request  Base64 URL-encoded OCSPReq payload
     * @return DER-encoded OCSPResp payload
     */
    @GetMapping(
            value = "/{caSerialNumber}/{base64Request}",
            produces = {OCSP_RESPONSE_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE}
    )
    // @PreAuthorize("permitAll()")
    public ResponseEntity<byte[]> handleOcspGet(
            @PathVariable String caSerialNumber,
            @PathVariable String base64Request) {

        try {
            String decodedUrl = URLDecoder.decode(base64Request, StandardCharsets.UTF_8);
            byte[] requestBytes;
            try {
                requestBytes = Base64.getUrlDecoder().decode(decodedUrl);
            } catch (IllegalArgumentException e) {
                requestBytes = Base64.getDecoder().decode(decodedUrl);
            }

            byte[] responseDer = ocspService.processOcspRequest(requestBytes, caSerialNumber);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_RESPONSE_TYPE)
                    .body(responseDer);
        } catch (Exception e) {
            byte[] errorDer = ocspService.processOcspRequest(null, caSerialNumber);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_RESPONSE_TYPE)
                    .body(errorDer);
        }
    }
}

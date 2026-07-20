;;;
;;; Copyright (c) 2026 Salza2 contributors, All Rights Reserved
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;   * Redistributions in binary form must reproduce the above copyright
;;;     notice, this list of conditions and the following disclaimer in the
;;;     documentation and/or other materials provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED OR
;;; IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
;;; OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;;; IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
;;; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
;;; NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;;; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
;;; THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

(in-package #:salza2-test)

(defun make-fragment-collector ()
  (let ((output (make-array 128
                            :element-type '(unsigned-byte 8)
                            :adjustable t
                            :fill-pointer 0)))
    (values
     (lambda (buffer end)
       (dotimes (i end)
         (vector-push-extend (aref buffer i) output)))
     (lambda ()
       (prog1 (subseq output 0)
         (setf (fill-pointer output) 0))))))

(defun deterministic-octets (length &optional (seed 1))
  (let ((result (make-array length :element-type '(unsigned-byte 8)))
        (state seed))
    (dotimes (i length result)
      (setf state (ldb (byte 32 0)
                       (+ (* state 1103515245) 12345))
            (aref result i) (ldb (byte 8 16) state)))))

(defun partially-compress (data)
  (multiple-value-bind (callback take-fragment)
      (make-fragment-collector)
    (let ((compressor (make-instance 'salza2:zlib-compressor
                                     :callback callback)))
      (salza2:compress-octet-vector data compressor)
      (salza2:partial-flush-compression compressor)
      (prog1 (funcall take-fragment)
        (salza2:finish-compression compressor)))))

(define-test partial-flush-makes-each-packet-decodable
  (multiple-value-bind (callback take-fragment)
      (make-fragment-collector)
    (let ((compressor (make-instance 'salza2:zlib-compressor
                                     :callback callback))
          (inflater (chipz:make-dstate 'chipz:zlib)))
      ;; A fixed-Huffman literal in this range has a nine-bit code. Repeating
      ;; the operation walks through all possible partial-octet alignments.
      (loop repeat 8
            do
               (let ((packet (make-array 1
                                         :element-type '(unsigned-byte 8)
                                         :initial-element 200)))
                 (salza2:compress-octet-vector packet compressor)
                 (salza2:partial-flush-compression compressor)
                 (is equalp packet
                     (chipz:decompress nil inflater (funcall take-fragment)
                                       :buffer-size 16))))
      (salza2:finish-compression compressor)
      (is equalp #()
          (chipz:decompress nil inflater (funcall take-fragment)
                            :buffer-size 16))
      (is eq t (chipz:finish-dstate inflater)))))

(define-test partial-flush-preserves-dictionary
  (let ((packet (deterministic-octets 4096)))
    (multiple-value-bind (callback take-fragment)
        (make-fragment-collector)
      (let ((compressor (make-instance 'salza2:zlib-compressor
                                       :callback callback))
            (inflater (chipz:make-dstate 'chipz:zlib)))
        (salza2:compress-octet-vector packet compressor)
        (salza2:partial-flush-compression compressor)
        (is equalp packet
            (chipz:decompress nil inflater (funcall take-fragment)
                              :buffer-size (length packet)))

        (salza2:compress-octet-vector packet compressor)
        (salza2:partial-flush-compression compressor)
        (let ((second-fragment (funcall take-fragment)))
          (is equalp packet
              (chipz:decompress nil inflater second-fragment
                                :buffer-size (length packet)))
          (is < (length (partially-compress packet))
              (length second-fragment)))

        (salza2:finish-compression compressor)
        (chipz:decompress nil inflater (funcall take-fragment)
                          :buffer-size 16)
        (is eq t (chipz:finish-dstate inflater))))))

(define-test partial-flush-gzip-wraps-history-buffer
  (multiple-value-bind (callback take-fragment)
      (make-fragment-collector)
    (let ((compressor (make-instance 'salza2:gzip-compressor
                                     :callback callback))
          (inflater (chipz:make-dstate 'chipz:gzip)))
      ;; The first packet leaves the circular input offset in its second half.
      ;; Compressing the next 32k packet then makes the pending range wrap at
      ;; the 64k boundary. In particular, the gzip checksum must process that
      ;; range as two contiguous pieces.
      (dolist (packet (list (deterministic-octets 33052 4)
                            (deterministic-octets 32768 5)))
        (salza2:compress-octet-vector packet compressor)
        (salza2:partial-flush-compression compressor)
        (is equalp packet
            (chipz:decompress nil inflater (funcall take-fragment)
                              :buffer-size (length packet))))
      (salza2:finish-compression compressor)
      (is equalp #()
          (chipz:decompress nil inflater (funcall take-fragment)
                            :buffer-size 16))
      (is eq t (chipz:finish-dstate inflater)))))

(define-test reset-after-partial-flush-starts-fresh-context
  (multiple-value-bind (callback take-fragment)
      (make-fragment-collector)
    (let* ((compressor (make-instance 'salza2:zlib-compressor
                                      :callback callback))
           (first-packet (deterministic-octets 37))
           (first-inflater (chipz:make-dstate 'chipz:zlib)))
      (salza2:compress-octet-vector first-packet compressor)
      (salza2:partial-flush-compression compressor)
      (is equalp first-packet
          (chipz:decompress nil first-inflater (funcall take-fragment)
                            :buffer-size (length first-packet)))

      ;; At rekey, SSH discards the unfinished old inflater and starts a fresh
      ;; zlib context. RESET must likewise discard any retained output bits.
      (salza2:reset compressor)
      (let ((second-inflater (chipz:make-dstate 'chipz:zlib))
            (maximum-packet (deterministic-octets 32768 2))
            (following-packet (deterministic-octets 3 3)))
        (salza2:compress-octet-vector maximum-packet compressor)
        (salza2:partial-flush-compression compressor)
        (is equalp maximum-packet
            (chipz:decompress nil second-inflater (funcall take-fragment)
                              :buffer-size (length maximum-packet)))

        (salza2:compress-octet-vector following-packet compressor)
        (salza2:partial-flush-compression compressor)
        (is equalp following-packet
            (chipz:decompress nil second-inflater (funcall take-fragment)
                              :buffer-size (length following-packet)))

        (salza2:finish-compression compressor)
        (chipz:decompress nil second-inflater (funcall take-fragment)
                          :buffer-size 16)
        (is eq t (chipz:finish-dstate second-inflater))))))

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

COPY grade.py test.sh /tests/
RUN chmod 0555 /tests/test.sh && chmod 0444 /tests/grade.py

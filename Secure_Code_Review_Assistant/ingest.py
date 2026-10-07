"""Build and query a local FAISS index of secure-coding guidelines.

This module never executes source code. It only embeds guideline text.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
GUIDELINES_PATH = ROOT / "data" / "secure_coding_guidelines.txt"
INDEX_DIR = ROOT / "index"
FAISS_PATH = INDEX_DIR / "coding_rules.faiss"
METADATA_PATH = INDEX_DIR / "metadata.json"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None
_index = None
_metadata = None


class RagError(Exception):
    """Raised when the local knowledge base or index cannot be used."""


def split_rule_documents(text: str) -> list[dict]:
    """Split the knowledge base into one document per [RULE] block."""
    blocks = re.findall(r"\[RULE\](.*?)\[END RULE\]", text, flags=re.DOTALL | re.IGNORECASE)
    documents = []
    for block in blocks:
        fields = {}
        for key in (
            "ID",
            "TITLE",
            "DESCRIPTION",
            "WHY IT MATTERS",
            "LANGUAGES",
            "EXAMPLE",
            "RECOMMENDED PRACTICE",
            "SEVERITY GUIDANCE",
        ):
            match = re.search(
                rf"{re.escape(key)}:\s*(.*?)(?=\n[A-Z][A-Z /]+:|\Z)",
                block,
                flags=re.DOTALL | re.IGNORECASE,
            )
            fields[key.lower()] = match.group(1).strip() if match else ""
        rule_id = fields.get("id") or "UNKNOWN"
        title = fields.get("title") or "Untitled rule"
        body = " ".join(
            part
            for part in (
                fields.get("description"),
                fields.get("why it matters"),
                fields.get("example"),
                fields.get("recommended practice"),
                fields.get("severity guidance"),
                fields.get("languages"),
            )
            if part
        )
        documents.append(
            {
                "id": rule_id,
                "title": title,
                "languages": fields.get("languages", ""),
                "text": f"{rule_id} {title}. {body}",
                "fields": fields,
            }
        )
    if not documents:
        raise RagError("No [RULE] blocks were found in the knowledge base.")
    return documents


def get_embedding_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _model


def build_index() -> None:
    if not GUIDELINES_PATH.exists():
        raise RagError(f"Knowledge base is missing: {GUIDELINES_PATH}")

    text = GUIDELINES_PATH.read_text(encoding="utf-8")
    documents = split_rule_documents(text)
    model = get_embedding_model()
    embeddings = model.encode(
        [doc["text"] for doc in documents],
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    embeddings = np.asarray(embeddings, dtype="float32")
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    norms = np.clip(norms, 1e-12, None)
    embeddings = embeddings / norms

    import faiss

    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(embeddings)

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(FAISS_PATH))
    METADATA_PATH.write_text(json.dumps(documents, indent=2), encoding="utf-8")
    print(f"Indexed {len(documents)} rules into {FAISS_PATH}")


def load_index():
    global _index, _metadata
    if _index is not None and _metadata is not None:
        return _index, _metadata

    if not FAISS_PATH.exists() or not METADATA_PATH.exists():
        raise RagError(
            "RAG index is missing. Run `python ingest.py` to build "
            f"{FAISS_PATH.name} and {METADATA_PATH.name}."
        )

    import faiss

    _index = faiss.read_index(str(FAISS_PATH))
    _metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    return _index, _metadata


def retrieve_rules(query: str, top_k: int = 3) -> list[dict]:
    """Return the most similar guideline documents for a query."""
    if not query or not query.strip():
        return []
    try:
        index, metadata = load_index()
        model = get_embedding_model()
        vector = model.encode([query], convert_to_numpy=True)
        vector = np.asarray(vector, dtype="float32")
        norm = np.linalg.norm(vector, axis=1, keepdims=True)
        vector = vector / np.clip(norm, 1e-12, None)
        k = max(1, min(int(top_k), len(metadata)))
        scores, ids = index.search(vector, k)
        results = []
        for score, doc_id in zip(scores[0], ids[0]):
            if doc_id < 0 or doc_id >= len(metadata):
                continue
            item = dict(metadata[doc_id])
            item["score"] = float(score)
            results.append(item)
        return results
    except RagError:
        raise
    except Exception as exc:
        raise RagError("RAG retrieval failed. Rebuild the index with `python ingest.py`.") from exc


def format_retrieved_rules(rules: list[dict]) -> str:
    lines = []
    for rule in rules:
        fields = rule.get("fields") or {}
        lines.append(
            f"{rule.get('id', '')} - {rule.get('title', '')}\n"
            f"Languages: {rule.get('languages', '')}\n"
            f"Description: {fields.get('description', '')}\n"
            f"Recommended practice: {fields.get('recommended practice', '')}"
        )
    return "\n\n".join(lines)


if __name__ == "__main__":
    os.chdir(ROOT)
    build_index()

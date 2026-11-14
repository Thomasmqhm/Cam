package com.camctl.core

import org.json.JSONArray
import org.json.JSONObject

/** Small helpers over Android's built-in org.json to write the camera's nested JSON without ceremony. */
fun toJson(v: Any?): Any = when (v) {
    null -> JSONObject.NULL
    is JSONObject, is JSONArray, is String, is Number, is Boolean -> v
    is Map<*, *> -> JSONObject().also { o -> v.forEach { (k, x) -> o.put(k.toString(), toJson(x)) } }
    is Iterable<*> -> JSONArray().also { a -> v.forEach { a.put(toJson(it)) } }
    is Array<*> -> JSONArray().also { a -> v.forEach { a.put(toJson(it)) } }
    else -> v.toString()
}

fun jo(vararg pairs: Pair<String, Any?>): JSONObject = JSONObject().also { o -> pairs.forEach { (k, v) -> o.put(k, toJson(v)) } }

fun parseObject(text: String): JSONObject = try {
    JSONObject(text)
} catch (e: Exception) {
    throw TapoException(null, "Réponse non JSON: ${text.take(200)}")
}

/** Navigate with a path of keys; returns null if any step is missing. */
fun Any?.at(vararg path: String): Any? {
    var cur: Any? = this
    for (k in path) {
        cur = (cur as? JSONObject)?.opt(k) ?: return null
        if (cur == JSONObject.NULL) return null
    }
    return cur
}

fun Any?.obj(vararg path: String): JSONObject? = at(*path) as? JSONObject

fun Any?.str(vararg path: String): String? = when (val v = at(*path)) {
    null, is JSONObject, is JSONArray -> null
    else -> v.toString()
}

fun Any?.int(vararg path: String): Int? = when (val v = at(*path)) {
    is Number -> v.toInt()
    is String -> v.toIntOrNull()
    else -> null
}

fun Any?.errorCode(): Int = int("error_code") ?: 0

fun JSONArray.items(): List<Any?> = (0 until length()).map { opt(it) }
fun JSONArray.objects(): List<JSONObject> = items().filterIsInstance<JSONObject>()

fun Any?.stringList(vararg path: String): List<String> =
    (at(*path) as? JSONArray)?.items()?.filter { it != null && it != JSONObject.NULL }?.map { it.toString() } ?: emptyList()

fun Any?.intList(vararg path: String): List<Int> = stringList(*path).mapNotNull { it.toIntOrNull() }

fun Any.pretty(): String = when (this) {
    is JSONObject -> toString(2)
    is JSONArray -> toString(2)
    else -> toString()
}

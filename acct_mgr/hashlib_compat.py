try:
    from hashlib import md5, sha1
except ImportError:
    import md5
    md5 = md5.new
    import sha
    sha1 = sha.new

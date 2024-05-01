class AppTransaction():
    def __init__(self,pipe):
        self.pipe =pipe
        self.befor_multi =[]
        self.after_multi =[]

    def execute(self):
        try:

            for func, args, kwargs in self.befor_multi:
                result = func(*args, **kwargs)
                if not (result is None):
                    return result


            self.pipe.multi()

            for func, args, kwargs in self.after_multi:
                 func(*args, **kwargs)


            self.pipe.execute()
            return "OK", 200
        except Exception as e:
            # If there's an error (like WatchError or other Redis errors), the transaction failed
            return e, 409


    def append_before_multi(self,value):
        self.befor_multi.append(value)


    def append_after_multi(self,value):
        self.after_multi.append(value)



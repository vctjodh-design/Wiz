import { Router, type IRouter } from "express";
import healthRouter from "./health";
import browserRouter from "./browser";

const router: IRouter = Router();

router.use(healthRouter);
router.use(browserRouter);

export default router;

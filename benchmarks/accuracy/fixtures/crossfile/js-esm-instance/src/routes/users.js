import Repo from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();

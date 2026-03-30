require("./setup");
import { assert } from "chai";
import { GuardianKeySet } from "../src/guardian";

describe("GuardianKeySet Tests", () => {
  it("should export GuardianKeySet class with static generate method", async () => {
    assert.isFunction(
      GuardianKeySet.generate,
      "GuardianKeySet.generate should be a function"
    );
  });

  it("should have votePublicKey, dataPublicKey, communicationPublicKey accessor shape", () => {
    // Verify the class prototype has the expected accessor descriptors
    const proto = GuardianKeySet.prototype;
    const voteDesc = Object.getOwnPropertyDescriptor(proto, "votePublicKey");
    const dataDesc = Object.getOwnPropertyDescriptor(proto, "dataPublicKey");
    const commDesc = Object.getOwnPropertyDescriptor(proto, "communicationPublicKey");
    assert.isObject(voteDesc, "votePublicKey accessor should exist");
    assert.isObject(dataDesc, "dataPublicKey accessor should exist");
    assert.isObject(commDesc, "communicationPublicKey accessor should exist");
  });
});
